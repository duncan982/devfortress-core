// Mock dependencies
jest.mock('../../../lib/logger', () => ({
  logInfo: jest.fn(),
  logError: jest.fn(),
}));

jest.mock('../../../lib/alerts/real-time-alerts', () => ({
  broadcastAlert: jest.fn(),
}));

jest.mock('@prisma/client', () => ({
  PrismaClient: jest.fn().mockImplementation(() => ({
    liveThreatEvent: {
      create: jest.fn(),
      findMany: jest.fn(),
      count: jest.fn(),
      deleteMany: jest.fn(),
    },
    apiProject: {
      findFirst: jest.fn(),
      findMany: jest.fn(),
      update: jest.fn(),
    },
    project: {
      findUnique: jest.fn(),
      update: jest.fn(),
    },
    surveillanceApiKey: {
      findUnique: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
    },
  })),
  ThreatSeverity: {
    LOW: 'LOW',
    MEDIUM: 'MEDIUM',
    HIGH: 'HIGH',
    CRITICAL: 'CRITICAL',
  },
}));

import {
  generateSurveillanceApiKey,
  validateSurveillanceApiKey,
  ingestLiveEvent,
  getLiveEvents,
  getLiveEventStats,
  generateProjectApiKey,
  revokeProjectApiKey,
  cleanupOldEvents,
  DATA_RETENTION_DAYS,
  EVENT_RATE_LIMITS,
} from '../../../lib/surveillance/live-surveillance';

import { PrismaClient } from '@prisma/client';
import { logInfo, logError } from '../../../lib/logger';
import { broadcastAlert } from '../../../lib/alerts/real-time-alerts';

const mockPrisma = new PrismaClient();
const mockLiveThreatEventCreate = mockPrisma.liveThreatEvent
  .create as jest.MockedFunction<any>;
const mockLiveThreatEventFindMany = mockPrisma.liveThreatEvent
  .findMany as jest.MockedFunction<any>;
const mockLiveThreatEventCount = mockPrisma.liveThreatEvent
  .count as jest.MockedFunction<any>;
const mockLiveThreatEventDeleteMany = mockPrisma.liveThreatEvent
  .deleteMany as jest.MockedFunction<any>;
const mockApiProjectFindFirst = mockPrisma.apiProject
  .findFirst as jest.MockedFunction<any>;
const mockApiProjectFindMany = mockPrisma.apiProject
  .findMany as jest.MockedFunction<any>;
const mockLogInfo = logInfo as jest.MockedFunction<typeof logInfo>;
const mockLogError = logError as jest.MockedFunction<typeof logError>;
const mockBroadcastAlert = broadcastAlert as jest.MockedFunction<
  typeof broadcastAlert
>;

describe('Live Surveillance Service', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('generateSurveillanceApiKey', () => {
    it('should generate a valid API key', () => {
      const key = generateSurveillanceApiKey();
      expect(typeof key).toBe('string');
      expect(key.length).toBeGreaterThan(0);
      expect(key.startsWith('vx_live_')).toBe(true);
    });
  });

  describe('validateSurveillanceApiKey', () => {
    it.skip('should validate a correct API key', async () => {
      mockApiProjectFindFirst.mockResolvedValue({
        id: 'project-1',
        userId: 'user-1',
        name: 'Test Project',
        surveillanceApiKey: 'hashed-key',
        createdAt: new Date(),
        updatedAt: new Date(),
        slug: 'test-project',
      });

      const result = await validateSurveillanceApiKey('sk_live_test');
      expect(result.valid).toBe(true);
      expect(result.project?.id).toBe('project-1');
    });

    it('should reject invalid API key', async () => {
      mockApiProjectFindFirst.mockResolvedValue(null);

      const result = await validateSurveillanceApiKey('invalid-key');
      expect(result.valid).toBe(false);
      expect(result.project?.id).toBeUndefined();
    });
  });

  describe('ingestLiveEvent', () => {
    it('should ingest and store live event', async () => {
      const event = {
        eventType: 'auth_failure',
        ip: '192.168.1.1',
        timestamp: new Date(),
        severity: 'HIGH' as const,
      };

      mockLiveThreatEventCreate.mockResolvedValue({
        id: '1',
        eventType: event.eventType,
        ip: event.ip,
        timestamp: event.timestamp || new Date(),
        severity: event.severity || 'LOW',
        createdAt: new Date(),
        updatedAt: new Date(),
        projectId: 'project-1',
        userAgent: null,
        requestPath: null,
        statusCode: null,
        method: null,
        headers: null,
        body: null,
        metadata: null,
      });

      await ingestLiveEvent('project-1', 'owner-1', 'FREE', event);

      expect(mockLiveThreatEventCreate).toHaveBeenCalled();
      expect(mockLogInfo).toHaveBeenCalled();
    });

    it('should broadcast alert for high severity events', async () => {
      const event = {
        eventType: 'injection_attempt',
        ip: '192.168.1.1',
        severity: 'CRITICAL' as const,
      };

      mockLiveThreatEventCreate.mockResolvedValue({
        id: '1',
        eventType: event.eventType,
        ip: event.ip,
        timestamp: new Date(),
        severity: event.severity || 'LOW',
        createdAt: new Date(),
        updatedAt: new Date(),
        projectId: 'project-1',
        userAgent: null,
        requestPath: null,
        statusCode: null,
        method: null,
        headers: null,
        body: null,
        metadata: null,
      });

      await ingestLiveEvent('project-1', 'owner-1', 'FREE', event);

      expect(mockBroadcastAlert).toHaveBeenCalled();
    });

    it('should handle ingestion errors', async () => {
      mockLiveThreatEventCreate.mockRejectedValue(new Error('DB error'));

      await expect(
        ingestLiveEvent('project-1', 'owner-1', 'FREE', {
          eventType: 'test',
          ip: '127.0.0.1',
        })
      ).rejects.toThrow();

      expect(mockLogError).toHaveBeenCalled();
    });
  });

  describe('getLiveEvents', () => {
    it('should retrieve live events with filters', async () => {
      const mockEvents = [
        {
          id: '1',
          eventType: 'auth_failure',
          ip: '192.168.1.1',
          severity: 'HIGH',
          createdAt: new Date(),
        },
      ];

      mockLiveThreatEventFindMany.mockResolvedValue(mockEvents);
      mockLiveThreatEventCount.mockResolvedValue(1);

      const result = await getLiveEvents('project-1', {
        limit: 10,
        offset: 0,
        severity: 'HIGH',
      });

      expect(result.events).toEqual(mockEvents);
      expect(mockLiveThreatEventFindMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            projectId: 'project-1',
            severity: 'HIGH',
          }),
          take: 10,
          skip: 0,
        })
      );
    });
  });

  describe('getLiveEventStats', () => {
    it('should return event statistics', async () => {
      const mockEvents = [
        {
          severity: 'HIGH' as const,
          eventType: 'auth_failure',
          ip: '192.168.1.1',
          requestPath: '/api/login',
          timestamp: new Date(),
        },
      ];

      mockLiveThreatEventFindMany.mockResolvedValue(mockEvents);

      const result = await getLiveEventStats('project-1');

      expect(result.total).toBe(1);
      expect(result.bySeverity.HIGH).toBe(1);
      expect(result.byType.auth_failure).toBe(1);
    });
  });

  describe('generateProjectApiKey', () => {
    it('should generate and store API key for project', async () => {
      mockApiProjectFindFirst.mockResolvedValue({
        id: 'project-1',
        name: 'Test Project',
        createdById: 'user-1',
      });

      const result = await generateProjectApiKey('project-1', 'user-1');

      expect(result.apiKey).toMatch(/^sk_live_/);
      expect(result.success).toBe(true);
      expect(mockPrisma.apiProject.update).toHaveBeenCalled();
    });

    it('should throw error for non-existent project', async () => {
      mockApiProjectFindFirst.mockResolvedValue(null);

      const result = await generateProjectApiKey('invalid-project', 'user-1');
      expect(result.success).toBe(false);
      expect(result.error).toContain('Project not found');
    });
  });

  describe('revokeProjectApiKey', () => {
    it('should revoke API key', async () => {
      mockApiProjectFindFirst.mockResolvedValue({
        id: 'project-1',
        surveillanceApiKey: 'sk_live_test',
      });

      const result = await revokeProjectApiKey('project-1', 'user-1');

      expect(result.success).toBe(true);
      expect(mockPrisma.apiProject.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: 'project-1' },
          data: { surveillanceApiKey: null },
        })
      );
    });
  });

  describe('cleanupOldEvents', () => {
    it('should cleanup old events in dry run mode', async () => {
      mockApiProjectFindMany.mockResolvedValue([]);

      const result = await cleanupOldEvents(true);

      expect(result.deleted).toBe(0); // Dry run
      expect(result.projects).toBe(0);
      expect(mockLiveThreatEventDeleteMany).not.toHaveBeenCalled();
    });

    it('should actually delete events when not dry run', async () => {
      mockLiveThreatEventCount.mockResolvedValue(10);
      mockLiveThreatEventDeleteMany.mockResolvedValue({ count: 5 });

      const result = await cleanupOldEvents(false);

      expect(result.deleted).toBe(5);
      expect(mockLiveThreatEventDeleteMany).toHaveBeenCalled();
    });
  });

  describe('Constants', () => {
    it('should have correct data retention days', () => {
      expect(DATA_RETENTION_DAYS.STARTER).toBe(7);
      expect(DATA_RETENTION_DAYS.PRO).toBe(30);
      expect(DATA_RETENTION_DAYS.ENTERPRISE).toBe(90);
    });

    it('should have correct event rate limits', () => {
      expect(EVENT_RATE_LIMITS.STARTER).toBe(100);
      expect(EVENT_RATE_LIMITS.PRO).toBe(500);
      expect(EVENT_RATE_LIMITS.ENTERPRISE).toBe(2000);
    });
  });
});
