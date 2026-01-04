/**
 * Threat event service
 * Manages threat event queries, statistics, and analysis
 */

import { PrismaClient, ThreatSeverity, ThreatEvent } from '@prisma/client';
import { logInfo, logError } from '../logger';

const prisma = new PrismaClient();

export interface ThreatEventFilters {
  honeypotId?: string;
  ownerId?: string;
  severity?: ThreatSeverity | ThreatSeverity[];
  attackPatterns?: string[];
  startDate?: Date;
  endDate?: Date;
  sourceIp?: string;
}

export interface ThreatEventStats {
  total: number;
  bySeverity: Record<ThreatSeverity, number>;
  byPattern: Record<string, number>;
  topSourceIps: Array<{ ip: string; count: number }>;
  recentEvents: number;
  criticalEvents: number;
}

export interface ThreatEventsResult {
  events: Array<
    ThreatEvent & { honeypot: { id: string; name: string; slug: string } }
  >;
  total: number;
  limit: number;
  offset: number;
}

/**
 * Get threat events with filters
 */
export async function getThreatEvents(
  filters: ThreatEventFilters,
  limit: number = 100,
  offset: number = 0
): Promise<ThreatEventsResult> {
  try {
     
    const where: any = {};

    if (filters.honeypotId) {
      where.honeypotId = filters.honeypotId;
    }

    if (filters.ownerId) {
      where.honeypot = {
        ownerId: filters.ownerId,
      };
    }

    if (filters.severity) {
      where.severity = Array.isArray(filters.severity)
        ? { in: filters.severity }
        : filters.severity;
    }

    if (filters.attackPatterns && filters.attackPatterns.length > 0) {
      where.tags = {
        hasSome: filters.attackPatterns,
      };
    }

    if (filters.startDate || filters.endDate) {
      where.detectedAt = {};
      if (filters.startDate) {
        where.detectedAt.gte = filters.startDate;
      }
      if (filters.endDate) {
        where.detectedAt.lte = filters.endDate;
      }
    }

    if (filters.sourceIp) {
      where.sourceIp = filters.sourceIp;
    }

    const events = await prisma.threatEvent.findMany({
      where,
      include: {
        honeypot: {
          select: {
            id: true,
            name: true,
            slug: true,
          },
        },
      },
      orderBy: {
        detectedAt: 'desc',
      },
      take: limit,
      skip: offset,
    });

    const total = await prisma.threatEvent.count({ where });

    return {
      events,
      total,
      limit,
      offset,
    };
  } catch (error) {
    // Log and return safe defaults so server components don't crash
    logError('Failed to get threat events - returning safe defaults', {
      error,
      filters,
    });
    return {
      events: [],
      total: 0,
      limit,
      offset,
    };
  }
}

/**
 * Get threat event statistics
 */
export async function getThreatEventStats(
  filters: ThreatEventFilters
): Promise<ThreatEventStats> {
  try {
     
    const where: any = {};

    if (filters.honeypotId) {
      where.honeypotId = filters.honeypotId;
    }

    if (filters.ownerId) {
      where.honeypot = {
        ownerId: filters.ownerId,
      };
    }

    if (filters.startDate || filters.endDate) {
      where.detectedAt = {};
      if (filters.startDate) {
        where.detectedAt.gte = filters.startDate;
      }
      if (filters.endDate) {
        where.detectedAt.lte = filters.endDate;
      }
    }

    // Total count
    const total = await prisma.threatEvent.count({ where });

    // Count by severity
    const severityCounts = await prisma.threatEvent.groupBy({
      by: ['severity'],
      where,
      _count: {
        id: true,
      },
    });

    const bySeverity: Record<ThreatSeverity, number> = {
      LOW: 0,
      MEDIUM: 0,
      HIGH: 0,
      CRITICAL: 0,
    };

    severityCounts.forEach(item => {
      bySeverity[item.severity] = item._count.id;
    });

    // Get all events to count patterns (limited approach for now)
    const allEvents = await prisma.threatEvent.findMany({
      where,
      select: {
        tags: true,
        sourceIp: true,
      },
    });

    // Count by attack pattern
    const patternCounts: Record<string, number> = {};
    allEvents.forEach(event => {
      if (event.tags && Array.isArray(event.tags)) {
        event.tags.forEach((pattern: string) => {
          patternCounts[pattern] = (patternCounts[pattern] || 0) + 1;
        });
      }
    });

    // Top source IPs
    const ipCounts: Record<string, number> = {};
    allEvents.forEach(event => {
      ipCounts[event.sourceIp] = (ipCounts[event.sourceIp] || 0) + 1;
    });

    const topSourceIps = Object.entries(ipCounts)
      .map(([ip, count]) => ({ ip, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    // Recent events (last 24 hours)
    const oneDayAgo = new Date();
    oneDayAgo.setDate(oneDayAgo.getDate() - 1);

    const recentEvents = await prisma.threatEvent.count({
      where: {
        ...where,
        detectedAt: {
          gte: oneDayAgo,
        },
      },
    });

    // Critical events
    const criticalEvents = await prisma.threatEvent.count({
      where: {
        ...where,
        severity: ThreatSeverity.CRITICAL,
      },
    });

    return {
      total,
      bySeverity,
      byPattern: patternCounts,
      topSourceIps,
      recentEvents,
      criticalEvents,
    };
  } catch (error) {
    // Return zeroed stats so UI can render an empty state instead of crashing
    logError('Failed to get threat event stats - returning safe defaults', {
      error,
      filters,
    });

    return {
      total: 0,
      bySeverity: {
        LOW: 0,
        MEDIUM: 0,
        HIGH: 0,
        CRITICAL: 0,
      },
      byPattern: {},
      topSourceIps: [],
      recentEvents: 0,
      criticalEvents: 0,
    };
  }
}

/**
 * Get single threat event by ID
 */
export async function getThreatEvent(threatEventId: string) {
  try {
    const event = await prisma.threatEvent.findUnique({
      where: { id: threatEventId },
      include: {
        honeypot: {
          select: {
            id: true,
            name: true,
            slug: true,
            deploymentUrl: true,
            owner: {
              select: {
                id: true,
                name: true,
                email: true,
              },
            },
          },
        },
      },
    });

    return event;
  } catch (error) {
    logError('Failed to get threat event - returning null', {
      error,
      threatEventId,
    });
    return null;
  }
}

/**
 * Delete old threat events (cleanup)
 */
export async function deleteOldThreatEvents(daysToKeep: number = 90) {
  try {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);

    const result = await prisma.threatEvent.deleteMany({
      where: {
        detectedAt: {
          lt: cutoffDate,
        },
      },
    });

    logInfo('Deleted old threat events', {
      count: result.count,
      cutoffDate,
    });

    return result.count;
  } catch (error) {
    logError('Failed to delete old threat events', { error });
    // For cleanup tasks return 0 on failure
    return 0;
  }
}

/**
 * Get threat trend data (events over time)
 */
export async function getThreatTrend(
  filters: ThreatEventFilters,
  intervalDays: number = 7
) {
  try {
    const endDate = filters.endDate || new Date();
    const startDate =
      filters.startDate ||
      new Date(endDate.getTime() - intervalDays * 24 * 60 * 60 * 1000);

     
    const where: any = {
      detectedAt: {
        gte: startDate,
        lte: endDate,
      },
    };

    if (filters.honeypotId) {
      where.honeypotId = filters.honeypotId;
    }

    if (filters.ownerId) {
      where.honeypot = {
        ownerId: filters.ownerId,
      };
    }

    const events = await prisma.threatEvent.findMany({
      where,
      select: {
        detectedAt: true,
        severity: true,
      },
      orderBy: {
        detectedAt: 'asc',
      },
    });

    // Group by day
    const trendData: Record<
      string,
      {
        date: string;
        count: number;
        severityCounts: Record<ThreatSeverity, number>;
      }
    > = {};

    events.forEach(event => {
      const dateKey = event.detectedAt.toISOString().split('T')[0];

      if (!trendData[dateKey]) {
        trendData[dateKey] = {
          date: dateKey,
          count: 0,
          severityCounts: {
            LOW: 0,
            MEDIUM: 0,
            HIGH: 0,
            CRITICAL: 0,
          },
        };
      }

      trendData[dateKey].count++;
      trendData[dateKey].severityCounts[event.severity]++;
    });

    return Object.values(trendData);
  } catch (error) {
    logError('Failed to get threat trend - returning empty array', {
      error,
      filters,
    });
    return [];
  }
}
