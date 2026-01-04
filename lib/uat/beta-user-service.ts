/**
 * Beta User Service for User Acceptance Testing
 * Manages beta testers, feedback collection, and test scenarios
 */

import { Prisma } from '@prisma/client';
import { prisma } from '@core/lib/prisma';
import { logInfo, logError } from '@core/lib/logger';

// Type definitions matching Prisma schema enums (uppercase)
export enum BetaUserRole {
  TESTER = 'TESTER',
  LEAD_TESTER = 'LEAD_TESTER',
  OBSERVER = 'OBSERVER',
}

export enum BetaUserStatus {
  INVITED = 'INVITED',
  ACTIVE = 'ACTIVE',
  INACTIVE = 'INACTIVE',
  COMPLETED = 'COMPLETED',
}

export enum TestScenarioCategory {
  API_GENERATION = 'API_GENERATION',
  SECURITY_SCAN = 'SECURITY_SCAN',
  DEPLOYMENT = 'DEPLOYMENT',
  MONITORING = 'MONITORING',
  GENERAL = 'GENERAL',
}

export enum TestScenarioPriority {
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
}

export enum TestScenarioStatus {
  DRAFT = 'DRAFT',
  ACTIVE = 'ACTIVE',
  COMPLETED = 'COMPLETED',
  DEPRECATED = 'DEPRECATED',
}

export enum FeedbackType {
  BUG = 'BUG',
  FEATURE_REQUEST = 'FEATURE_REQUEST',
  USABILITY = 'USABILITY',
  PERFORMANCE = 'PERFORMANCE',
  GENERAL = 'GENERAL',
}

export enum FeedbackSeverity {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
}

export enum FeedbackStatus {
  NEW = 'NEW',
  TRIAGED = 'TRIAGED',
  IN_PROGRESS = 'IN_PROGRESS',
  RESOLVED = 'RESOLVED',
  WONT_FIX = 'WONT_FIX',
}

const normalizeEnumValue = <T extends string>(
  value: T | string,
  mapping: Record<string, T>,
  label: string
): T => {
  const normalizedKey = value.toLowerCase();
  const result = mapping[normalizedKey];

  if (!result) {
    throw new Error(`Invalid ${label}: ${value}`);
  }

  return result;
};

const BETA_USER_ROLE_MAP: Record<string, BetaUserRole> = {
  tester: BetaUserRole.TESTER,
  lead_tester: BetaUserRole.LEAD_TESTER,
  observer: BetaUserRole.OBSERVER,
};

const BETA_USER_STATUS_MAP: Record<string, BetaUserStatus> = {
  invited: BetaUserStatus.INVITED,
  active: BetaUserStatus.ACTIVE,
  inactive: BetaUserStatus.INACTIVE,
  completed: BetaUserStatus.COMPLETED,
};

const TEST_SCENARIO_CATEGORY_MAP: Record<string, TestScenarioCategory> = {
  api_generation: TestScenarioCategory.API_GENERATION,
  security_scan: TestScenarioCategory.SECURITY_SCAN,
  deployment: TestScenarioCategory.DEPLOYMENT,
  monitoring: TestScenarioCategory.MONITORING,
  general: TestScenarioCategory.GENERAL,
};

const TEST_SCENARIO_PRIORITY_MAP: Record<string, TestScenarioPriority> = {
  high: TestScenarioPriority.HIGH,
  medium: TestScenarioPriority.MEDIUM,
  low: TestScenarioPriority.LOW,
};

const TEST_SCENARIO_STATUS_MAP: Record<string, TestScenarioStatus> = {
  draft: TestScenarioStatus.DRAFT,
  active: TestScenarioStatus.ACTIVE,
  completed: TestScenarioStatus.COMPLETED,
  deprecated: TestScenarioStatus.DEPRECATED,
};

const FEEDBACK_TYPE_MAP: Record<string, FeedbackType> = {
  bug: FeedbackType.BUG,
  feature_request: FeedbackType.FEATURE_REQUEST,
  usability: FeedbackType.USABILITY,
  performance: FeedbackType.PERFORMANCE,
  general: FeedbackType.GENERAL,
};

const FEEDBACK_SEVERITY_MAP: Record<string, FeedbackSeverity> = {
  critical: FeedbackSeverity.CRITICAL,
  high: FeedbackSeverity.HIGH,
  medium: FeedbackSeverity.MEDIUM,
  low: FeedbackSeverity.LOW,
};

const FEEDBACK_STATUS_MAP: Record<string, FeedbackStatus> = {
  new: FeedbackStatus.NEW,
  triaged: FeedbackStatus.TRIAGED,
  in_progress: FeedbackStatus.IN_PROGRESS,
  resolved: FeedbackStatus.RESOLVED,
  wont_fix: FeedbackStatus.WONT_FIX,
};

type BetaUserRoleInput = BetaUserRole | keyof typeof BETA_USER_ROLE_MAP;
type BetaUserStatusInput = BetaUserStatus | keyof typeof BETA_USER_STATUS_MAP;
type ScenarioCategoryInput =
  | TestScenarioCategory
  | keyof typeof TEST_SCENARIO_CATEGORY_MAP;
type ScenarioPriorityInput =
  | TestScenarioPriority
  | keyof typeof TEST_SCENARIO_PRIORITY_MAP;
type ScenarioStatusInput =
  | TestScenarioStatus
  | keyof typeof TEST_SCENARIO_STATUS_MAP;
type FeedbackTypeInput = FeedbackType | keyof typeof FEEDBACK_TYPE_MAP;
type FeedbackSeverityInput =
  | FeedbackSeverity
  | keyof typeof FEEDBACK_SEVERITY_MAP;
type FeedbackStatusInput = FeedbackStatus | keyof typeof FEEDBACK_STATUS_MAP;

export type CreateScenarioInput = Omit<
  TestScenario,
  'id' | 'createdAt' | 'updatedAt' | 'category' | 'priority' | 'status'
> & {
  category: ScenarioCategoryInput;
  priority: ScenarioPriorityInput;
  status: ScenarioStatusInput;
};

export type ScenarioFiltersInput = {
  category?: ScenarioCategoryInput;
  priority?: ScenarioPriorityInput;
  status?: ScenarioStatusInput;
};

export type SubmitFeedbackInput = Omit<
  BetaFeedback,
  'id' | 'createdAt' | 'status' | 'type' | 'severity' | 'metadata'
> & {
  type: FeedbackTypeInput;
  severity: FeedbackSeverityInput;
  metadata?: Prisma.InputJsonValue | null;
};

export type FeedbackFiltersInput = {
  betaUserId?: string;
  scenarioId?: string;
  type?: FeedbackTypeInput;
  severity?: FeedbackSeverityInput;
  status?: FeedbackStatusInput;
};

export interface BetaUser {
  id: string;
  userId: string;
  email: string;
  role: BetaUserRole;
  status: BetaUserStatus;
  invitedAt: Date;
  activatedAt?: Date | null;
  completedAt?: Date | null;
  testScenarios: string[];
  feedbackCount: number;
  metadata?: Prisma.JsonObject | null;
}

export interface TestScenario {
  id: string;
  name: string;
  description: string;
  category: TestScenarioCategory;
  priority: TestScenarioPriority;
  steps: string[];
  expectedOutcome: string;
  status: TestScenarioStatus;
  createdAt: Date;
  updatedAt: Date;
}

export interface BetaFeedback {
  id: string;
  betaUserId: string;
  scenarioId?: string | null;
  type: FeedbackType;
  severity: FeedbackSeverity;
  title: string;
  description: string;
  steps?: string[];
  expectedBehavior?: string | null;
  actualBehavior?: string | null;
  screenshots?: string[];
  status: FeedbackStatus;
  createdAt: Date;
  resolvedAt?: Date | null;
  metadata?: Prisma.JsonObject | null;
}

export class BetaUserService {
  /**
   * Invite a user to beta testing program
   */
  static async inviteBetaUser(
    userId: string,
    email: string,
    role: BetaUserRoleInput = BetaUserRole.TESTER,
    scenarios: string[] = []
  ): Promise<BetaUser> {
    try {
      const normalizedRole = normalizeEnumValue(
        role,
        BETA_USER_ROLE_MAP,
        'beta user role'
      );

      logInfo('Inviting beta user', {
        userId,
        email,
        role: normalizedRole,
      });

      const betaUser = await prisma.betaUser.create({
        data: {
          userId,
          email,
          role: normalizedRole,
          status: BetaUserStatus.INVITED,
          invitedAt: new Date(),
          testScenarios: scenarios,
          feedbackCount: 0,
          metadata: {
            invitedBy: 'system',
            version: '1.0.0',
          },
        },
      });

      logInfo('Beta user invited successfully', { betaUserId: betaUser.id });
      return betaUser as BetaUser;
    } catch (error) {
      logError('Failed to invite beta user', { error, userId, email });
      throw new Error('Failed to invite beta user');
    }
  }

  /**
   * Activate a beta user after they accept invitation
   */
  static async activateBetaUser(betaUserId: string): Promise<BetaUser> {
    try {
      logInfo('Activating beta user', { betaUserId });

      const betaUser = await prisma.betaUser.update({
        where: { id: betaUserId },
        data: {
          status: BetaUserStatus.ACTIVE,
          activatedAt: new Date(),
        },
      });

      logInfo('Beta user activated successfully', { betaUserId });
      return betaUser as BetaUser;
    } catch (error) {
      logError('Failed to activate beta user', { error, betaUserId });
      throw new Error('Failed to activate beta user');
    }
  }

  /**
   * Get all beta users with optional filtering
   */
  static async getBetaUsers(filters?: {
    status?: BetaUserStatusInput;
    role?: BetaUserRoleInput;
  }): Promise<BetaUser[]> {
    try {
      const where = filters
        ? {
            ...(filters.status
              ? {
                  status: normalizeEnumValue(
                    filters.status,
                    BETA_USER_STATUS_MAP,
                    'beta user status'
                  ),
                }
              : {}),
            ...(filters.role
              ? {
                  role: normalizeEnumValue(
                    filters.role,
                    BETA_USER_ROLE_MAP,
                    'beta user role'
                  ),
                }
              : {}),
          }
        : undefined;

      const betaUsers = await prisma.betaUser.findMany({
        where,
        orderBy: { invitedAt: 'desc' },
      });

      return betaUsers as BetaUser[];
    } catch (error) {
      logError('Failed to get beta users', { error, filters });
      throw new Error('Failed to get beta users');
    }
  }

  /**
   * Create a new test scenario
   */
  static async createTestScenario(
    scenario: CreateScenarioInput
  ): Promise<TestScenario> {
    try {
      const normalizedScenario = {
        ...scenario,
        category: normalizeEnumValue(
          scenario.category,
          TEST_SCENARIO_CATEGORY_MAP,
          'test scenario category'
        ),
        priority: normalizeEnumValue(
          scenario.priority,
          TEST_SCENARIO_PRIORITY_MAP,
          'test scenario priority'
        ),
        status: normalizeEnumValue(
          scenario.status,
          TEST_SCENARIO_STATUS_MAP,
          'test scenario status'
        ),
      };

      logInfo('Creating test scenario', { name: normalizedScenario.name });

      const testScenario = await prisma.testScenario.create({
        data: {
          ...normalizedScenario,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      });

      logInfo('Test scenario created successfully', {
        scenarioId: testScenario.id,
      });
      return testScenario as TestScenario;
    } catch (error) {
      logError('Failed to create test scenario', { error, scenario });
      throw new Error('Failed to create test scenario');
    }
  }

  /**
   * Get all test scenarios with optional filtering
   */
  static async getTestScenarios(
    filters?: ScenarioFiltersInput
  ): Promise<TestScenario[]> {
    try {
      const where = filters
        ? {
            ...(filters.category
              ? {
                  category: normalizeEnumValue(
                    filters.category,
                    TEST_SCENARIO_CATEGORY_MAP,
                    'test scenario category'
                  ),
                }
              : {}),
            ...(filters.priority
              ? {
                  priority: normalizeEnumValue(
                    filters.priority,
                    TEST_SCENARIO_PRIORITY_MAP,
                    'test scenario priority'
                  ),
                }
              : {}),
            ...(filters.status
              ? {
                  status: normalizeEnumValue(
                    filters.status,
                    TEST_SCENARIO_STATUS_MAP,
                    'test scenario status'
                  ),
                }
              : {}),
          }
        : undefined;

      const scenarios = await prisma.testScenario.findMany({
        where,
        orderBy: [{ priority: 'asc' }, { createdAt: 'desc' }],
      });

      return scenarios as TestScenario[];
    } catch (error) {
      logError('Failed to get test scenarios', { error, filters });
      throw new Error('Failed to get test scenarios');
    }
  }

  /**
   * Submit beta feedback
   */
  static async submitFeedback(
    feedback: SubmitFeedbackInput
  ): Promise<BetaFeedback> {
    try {
      const { metadata, type, severity, ...feedbackData } = feedback;

      const normalizedType = normalizeEnumValue(
        type,
        FEEDBACK_TYPE_MAP,
        'feedback type'
      );
      const normalizedSeverity = normalizeEnumValue(
        severity,
        FEEDBACK_SEVERITY_MAP,
        'feedback severity'
      );

      logInfo('Submitting beta feedback', {
        betaUserId: feedback.betaUserId,
        type: normalizedType,
        severity: normalizedSeverity,
      });

      const metadataJson =
        metadata === undefined || metadata === null
          ? Prisma.JsonNull
          : metadata;

      const newFeedback = await prisma.betaFeedback.create({
        data: {
          ...feedbackData,
          type: normalizedType,
          severity: normalizedSeverity,
          metadata: metadataJson,
          status: FeedbackStatus.NEW,
          createdAt: new Date(),
        },
      });

      // Increment feedback count for beta user
      await prisma.betaUser.update({
        where: { id: feedback.betaUserId },
        data: { feedbackCount: { increment: 1 } },
      });

      logInfo('Beta feedback submitted successfully', {
        feedbackId: newFeedback.id,
      });
      return newFeedback as BetaFeedback;
    } catch (error) {
      logError('Failed to submit beta feedback', { error, feedback });
      throw new Error('Failed to submit beta feedback');
    }
  }

  /**
   * Get feedback with optional filtering
   */
  static async getFeedback(
    filters?: FeedbackFiltersInput
  ): Promise<BetaFeedback[]> {
    try {
      const where = filters
        ? {
            betaUserId: filters.betaUserId,
            scenarioId: filters.scenarioId,
            ...(filters.type
              ? {
                  type: normalizeEnumValue(
                    filters.type,
                    FEEDBACK_TYPE_MAP,
                    'feedback type'
                  ),
                }
              : {}),
            ...(filters.severity
              ? {
                  severity: normalizeEnumValue(
                    filters.severity,
                    FEEDBACK_SEVERITY_MAP,
                    'feedback severity'
                  ),
                }
              : {}),
            ...(filters.status
              ? {
                  status: normalizeEnumValue(
                    filters.status,
                    FEEDBACK_STATUS_MAP,
                    'feedback status'
                  ),
                }
              : {}),
          }
        : undefined;

      const feedback = await prisma.betaFeedback.findMany({
        where,
        orderBy: [{ severity: 'asc' }, { createdAt: 'desc' }],
      });

      return feedback as BetaFeedback[];
    } catch (error) {
      logError('Failed to get beta feedback', { error, filters });
      throw new Error('Failed to get beta feedback');
    }
  }

  /**
   * Update feedback status
   */
  static async updateFeedbackStatus(
    feedbackId: string,
    status: FeedbackStatusInput
  ): Promise<BetaFeedback> {
    try {
      const normalizedStatus = normalizeEnumValue(
        status,
        FEEDBACK_STATUS_MAP,
        'feedback status'
      );

      logInfo('Updating feedback status', {
        feedbackId,
        status: normalizedStatus,
      });

      const updateData: Record<string, unknown> = {
        status: normalizedStatus,
      };
      if (normalizedStatus === FeedbackStatus.RESOLVED) {
        updateData.resolvedAt = new Date();
      }

      const feedback = await prisma.betaFeedback.update({
        where: { id: feedbackId },
        data: updateData,
      });

      logInfo('Feedback status updated successfully', { feedbackId });
      return feedback as BetaFeedback;
    } catch (error) {
      logError('Failed to update feedback status', { error, feedbackId });
      throw new Error('Failed to update feedback status');
    }
  }

  /**
   * Get beta testing statistics
   */
  static async getStatistics(): Promise<{
    totalBetaUsers: number;
    activeUsers: number;
    totalFeedback: number;
    criticalIssues: number;
    resolvedIssues: number;
    testScenarios: number;
    completedScenarios: number;
  }> {
    try {
      const [
        totalBetaUsers,
        activeUsers,
        totalFeedback,
        criticalIssues,
        resolvedIssues,
        testScenarios,
        completedScenarios,
      ] = await Promise.all([
        prisma.betaUser.count(),
        prisma.betaUser.count({
          where: { status: BetaUserStatus.ACTIVE },
        }),
        prisma.betaFeedback.count(),
        prisma.betaFeedback.count({
          where: { severity: FeedbackSeverity.CRITICAL },
        }),
        prisma.betaFeedback.count({
          where: { status: FeedbackStatus.RESOLVED },
        }),
        prisma.testScenario.count(),
        prisma.testScenario.count({
          where: { status: TestScenarioStatus.COMPLETED },
        }),
      ]);

      return {
        totalBetaUsers,
        activeUsers,
        totalFeedback,
        criticalIssues,
        resolvedIssues,
        testScenarios,
        completedScenarios,
      };
    } catch (error) {
      logError('Failed to get beta statistics', { error });
      throw new Error('Failed to get beta statistics');
    }
  }

  /**
   * Complete beta testing for a user
   */
  static async completeBetaTesting(betaUserId: string): Promise<BetaUser> {
    try {
      logInfo('Completing beta testing', { betaUserId });

      const betaUser = await prisma.betaUser.update({
        where: { id: betaUserId },
        data: {
          status: BetaUserStatus.COMPLETED,
          completedAt: new Date(),
        },
      });

      logInfo('Beta testing completed successfully', { betaUserId });
      return betaUser as BetaUser;
    } catch (error) {
      logError('Failed to complete beta testing', { error, betaUserId });
      throw new Error('Failed to complete beta testing');
    }
  }

  /**
   * Assign test scenarios to a beta user
   */
  static async assignTestScenarios(
    betaUserId: string,
    scenarioIds: string[]
  ): Promise<BetaUser> {
    try {
      logInfo('Assigning test scenarios', { betaUserId, scenarioIds });

      const betaUser = await prisma.betaUser.update({
        where: { id: betaUserId },
        data: {
          testScenarios: scenarioIds,
        },
      });

      logInfo('Test scenarios assigned successfully', { betaUserId });
      return betaUser as BetaUser;
    } catch (error) {
      logError('Failed to assign test scenarios', {
        error,
        betaUserId,
        scenarioIds,
      });
      throw new Error('Failed to assign test scenarios');
    }
  }
}
