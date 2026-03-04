/**
 * Hybrid AI Controller
 * Routes AI tasks between NL (GPT-4) and ML (Hugging Face) providers
 * Implements gradual migration strategy with monitoring and fallbacks
 */

import { AIProvider, AITaskType, Prisma } from '@prisma/client';
import { prisma } from './prisma';
import { logInfo, logError, logWarn, logDebug } from './logger';
import OpenAI from 'openai';
import * as crypto from 'crypto';

// Feature flags for gradual ML migration
interface MLFeatureFlags {
  USE_ML_FOR_SCANS: boolean;
  USE_ML_FOR_THREAT_ANALYSIS: boolean;
  USE_ML_FOR_API_GENERATION: boolean;
  USE_ML_FOR_VULNERABILITY_DETECTION: boolean;
  USE_ML_FOR_CODE_REVIEW: boolean;
  USE_ML_FOR_COMPLIANCE_CHECK: boolean;
}

// Configuration thresholds for auto-migration
interface MigrationThresholds {
  minAccuracy: number; // e.g., 0.90 for simple tasks, 0.95 for complex
  minSampleSize: number; // e.g., 100 samples before considering migration
  maxErrorRate: number; // e.g., 0.05 (5%)
  minWeeks: number; // e.g., 2-4 weeks of consistent performance
  pValueThreshold: number; // e.g., 0.05 for statistical significance
}

// Task complexity configuration
const TASK_THRESHOLDS: Record<AITaskType, MigrationThresholds> = {
  SECURITY_SCAN: {
    minAccuracy: 0.9,
    minSampleSize: 100,
    maxErrorRate: 0.05,
    minWeeks: 2,
    pValueThreshold: 0.05,
  },
  THREAT_ANALYSIS: {
    minAccuracy: 0.9,
    minSampleSize: 100,
    maxErrorRate: 0.05,
    minWeeks: 2,
    pValueThreshold: 0.05,
  },
  VULNERABILITY_DETECTION: {
    minAccuracy: 0.92,
    minSampleSize: 150,
    maxErrorRate: 0.04,
    minWeeks: 3,
    pValueThreshold: 0.05,
  },
  API_GENERATION: {
    minAccuracy: 0.95,
    minSampleSize: 200,
    maxErrorRate: 0.03,
    minWeeks: 4,
    pValueThreshold: 0.05,
  },
  CODE_REVIEW: {
    minAccuracy: 0.93,
    minSampleSize: 150,
    maxErrorRate: 0.04,
    minWeeks: 3,
    pValueThreshold: 0.05,
  },
  COMPLIANCE_CHECK: {
    minAccuracy: 0.95,
    minSampleSize: 100,
    maxErrorRate: 0.03,
    minWeeks: 3,
    pValueThreshold: 0.05,
  },
};

// Cost tracking
const COST_PER_TOKEN = {
  GPT4_INPUT: 0.00003, // $0.03 per 1K tokens
  GPT4_OUTPUT: 0.00006, // $0.06 per 1K tokens
  ML_HF: 0.0, // Free tier for now
};

interface AIRequest {
  taskType: AITaskType;
  prompt: string;
  context?: Record<string, unknown>;
  temperature?: number;
  maxTokens?: number;
}

interface AIResponse {
  provider: AIProvider;
  result: string;
  confidence?: number;
  costUsd: number;
  latencyMs: number;
  error?: string;
  nlUsedAsFallback?: boolean;
}

/**
 * Get feature flags from app settings
 */
async function getMLFeatureFlags(): Promise<MLFeatureFlags> {
  try {
    const enableML = await prisma.appSettings.findUnique({
      where: { key: 'enable_ml' },
    });

    const mlEnabled = enableML?.value === 'true';

    // Get individual feature flags
    const scanFlag = await prisma.appSettings.findUnique({
      where: { key: 'ml_feature_security_scan' },
    });
    const threatFlag = await prisma.appSettings.findUnique({
      where: { key: 'ml_feature_threat_analysis' },
    });
    const apiGenFlag = await prisma.appSettings.findUnique({
      where: { key: 'ml_feature_api_generation' },
    });
    const vulnFlag = await prisma.appSettings.findUnique({
      where: { key: 'ml_feature_vulnerability_detection' },
    });
    const reviewFlag = await prisma.appSettings.findUnique({
      where: { key: 'ml_feature_code_review' },
    });
    const complianceFlag = await prisma.appSettings.findUnique({
      where: { key: 'ml_feature_compliance_check' },
    });

    return {
      USE_ML_FOR_SCANS: mlEnabled && scanFlag?.value === 'true',
      USE_ML_FOR_THREAT_ANALYSIS: mlEnabled && threatFlag?.value === 'true',
      USE_ML_FOR_API_GENERATION: mlEnabled && apiGenFlag?.value === 'true',
      USE_ML_FOR_VULNERABILITY_DETECTION:
        mlEnabled && vulnFlag?.value === 'true',
      USE_ML_FOR_CODE_REVIEW: mlEnabled && reviewFlag?.value === 'true',
      USE_ML_FOR_COMPLIANCE_CHECK:
        mlEnabled && complianceFlag?.value === 'true',
    };
  } catch (error) {
    logError('Failed to fetch ML feature flags', { error });
    // Default to all false for safety
    return {
      USE_ML_FOR_SCANS: false,
      USE_ML_FOR_THREAT_ANALYSIS: false,
      USE_ML_FOR_API_GENERATION: false,
      USE_ML_FOR_VULNERABILITY_DETECTION: false,
      USE_ML_FOR_CODE_REVIEW: false,
      USE_ML_FOR_COMPLIANCE_CHECK: false,
    };
  }
}

/**
 * Determine if ML should be used for a specific task
 */
function shouldUseML(
  taskType: AITaskType,
  featureFlags: MLFeatureFlags
): boolean {
  switch (taskType) {
    case 'SECURITY_SCAN':
      return featureFlags.USE_ML_FOR_SCANS;
    case 'THREAT_ANALYSIS':
      return featureFlags.USE_ML_FOR_THREAT_ANALYSIS;
    case 'API_GENERATION':
      return featureFlags.USE_ML_FOR_API_GENERATION;
    case 'VULNERABILITY_DETECTION':
      return featureFlags.USE_ML_FOR_VULNERABILITY_DETECTION;
    case 'CODE_REVIEW':
      return featureFlags.USE_ML_FOR_CODE_REVIEW;
    case 'COMPLIANCE_CHECK':
      return featureFlags.USE_ML_FOR_COMPLIANCE_CHECK;
    default:
      return false;
  }
}

/**
 * Hash input for anonymized logging
 */
function hashInput(input: string): string {
  return crypto.createHash('sha256').update(input).digest('hex');
}

/**
 * Truncate output for logging (remove sensitive data)
 */
function anonymizeOutput(output: string, maxLength = 200): string {
  // Remove potential sensitive patterns
  const sanitized = output
    .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, '[EMAIL]')
    .replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[SSN]')
    .replace(/\b(?:\d{4}[-\s]?){3}\d{4}\b/g, '[CARD]')
    .replace(/\b[A-Z0-9]{20,}\b/g, '[TOKEN]');

  return sanitized.length > maxLength
    ? sanitized.substring(0, maxLength) + '...'
    : sanitized;
}

/**
 * Call NL (GPT-4) provider
 */
async function callNLProvider(request: AIRequest): Promise<AIResponse> {
  const startTime = Date.now();
  try {
    if (!process.env.OPENAI_API_KEY) {
      throw new Error('OpenAI API key not configured');
    }

    const openai = new OpenAI({
      apiKey: process.env.OPENAI_API_KEY,
    });

    const response = await openai.chat.completions.create({
      model: process.env.OPENAI_MODEL || 'gpt-4o-mini',
      messages: [
        {
          role: 'system',
          content: `You are an expert AI assistant for ${request.taskType} tasks.`,
        },
        {
          role: 'user',
          content: request.prompt,
        },
      ],
      temperature: request.temperature ?? 0.7,
      max_tokens: request.maxTokens ?? 2000,
    });

    const result = response.choices[0]?.message?.content ?? '';
    const latencyMs = Date.now() - startTime;

    // Calculate cost
    const inputTokens = response.usage?.prompt_tokens ?? 0;
    const outputTokens = response.usage?.completion_tokens ?? 0;
    const costUsd =
      inputTokens * COST_PER_TOKEN.GPT4_INPUT +
      outputTokens * COST_PER_TOKEN.GPT4_OUTPUT;

    logDebug('NL provider call successful', {
      taskType: request.taskType,
      latencyMs,
      costUsd,
      inputTokens,
      outputTokens,
    });

    return {
      provider: 'NL_GPT4',
      result,
      costUsd,
      latencyMs,
    };
  } catch (error) {
    const latencyMs = Date.now() - startTime;
    logError('NL provider call failed', {
      error,
      taskType: request.taskType,
      latencyMs,
    });
    throw error;
  }
}

/**
 * Call ML (Hugging Face) provider
 * Note: This is a placeholder for future ML integration
 */
async function callMLProvider(request: AIRequest): Promise<AIResponse> {
  const startTime = Date.now();
  try {
    // TODO: Implement Hugging Face Transformers integration
    // For now, this is a mock that simulates ML behavior
    logWarn('ML provider not yet implemented, using mock', {
      taskType: request.taskType,
    });

    // Simulate processing time
    await new Promise(resolve => setTimeout(resolve, 500));

    const latencyMs = Date.now() - startTime;

    // Mock response
    return {
      provider: 'ML_HF',
      result: `[ML Mock Result for ${request.taskType}]`,
      confidence: 0.85,
      costUsd: 0.0,
      latencyMs,
    };
  } catch (error) {
    const latencyMs = Date.now() - startTime;
    logError('ML provider call failed', {
      error,
      taskType: request.taskType,
      latencyMs,
    });
    throw error;
  }
}

/**
 * Log performance data to database
 */
async function logPerformance(
  request: AIRequest,
  response: AIResponse,
  errorOccurred = false,
  errorType?: string
): Promise<void> {
  try {
    const inputHash = hashInput(request.prompt);
    const outputSample = response.result
      ? anonymizeOutput(response.result)
      : null;

    await prisma.aIPerformanceLog.create({
      data: {
        taskType: request.taskType,
        provider: response.provider,
        inputHash,
        outputSample,
        accuracy: null, // Will be updated by monitoring system
        costUsd: response.costUsd,
        latencyMs: response.latencyMs,
        errorOccurred,
        errorType,
        mlConfidence: response.confidence,
        nlUsedAsFallback: response.nlUsedAsFallback ?? false,
        metadata: request.context as Prisma.InputJsonValue,
      },
    });

    logDebug('Performance data logged', {
      taskType: request.taskType,
      provider: response.provider,
      inputHash,
    });
  } catch (error) {
    // Don't throw - logging failures shouldn't break the main flow
    logError('Failed to log performance data', { error });
  }
}

/**
 * Main hybrid AI router
 */
export async function processAIRequest(
  request: AIRequest
): Promise<AIResponse> {
  logInfo('Processing AI request', { taskType: request.taskType });

  // Get feature flags
  const featureFlags = await getMLFeatureFlags();
  const useML = shouldUseML(request.taskType, featureFlags);

  let primaryResponse: AIResponse | null = null;
  let fallbackResponse: AIResponse | null = null;

  try {
    if (useML) {
      // Try ML first
      logDebug('Attempting ML provider', { taskType: request.taskType });
      try {
        primaryResponse = await callMLProvider(request);
        await logPerformance(request, primaryResponse);

        // Also call NL in parallel for comparison (passive learning)
        callNLProvider(request)
          .then(nlResponse => logPerformance(request, nlResponse))
          .catch(error =>
            logError('NL parallel call failed', {
              error,
              taskType: request.taskType,
            })
          );

        return primaryResponse;
      } catch (mlError) {
        // ML failed, fallback to NL
        logWarn('ML provider failed, falling back to NL', {
          error: mlError,
          taskType: request.taskType,
        });
        await logPerformance(
          request,
          {
            provider: 'ML_HF',
            result: '',
            costUsd: 0,
            latencyMs: 0,
          },
          true,
          (mlError as Error).message
        );

        fallbackResponse = await callNLProvider(request);
        fallbackResponse.nlUsedAsFallback = true;
        await logPerformance(request, fallbackResponse);
        return fallbackResponse;
      }
    } else {
      // Use NL by default
      logDebug('Using NL provider (ML disabled)', {
        taskType: request.taskType,
      });
      primaryResponse = await callNLProvider(request);
      await logPerformance(request, primaryResponse);

      // Run ML in parallel for passive learning if globally enabled
      const globalMLEnabled = await prisma.appSettings.findUnique({
        where: { key: 'enable_ml' },
      });
      if (globalMLEnabled?.value === 'true') {
        callMLProvider(request)
          .then(mlResponse => logPerformance(request, mlResponse))
          .catch(error =>
            logError('ML parallel call failed (passive learning)', {
              error,
              taskType: request.taskType,
            })
          );
      }

      return primaryResponse;
    }
  } catch (error) {
    logError('All AI providers failed', { error, taskType: request.taskType });
    throw new Error(
      `Failed to process AI request for ${request.taskType}: ${(error as Error).message}`
    );
  }
}

/**
 * Check if task meets migration thresholds
 */
export async function checkMigrationEligibility(taskType: AITaskType): Promise<{
  eligible: boolean;
  reason: string;
  metrics: {
    accuracy: number;
    errorRate: number;
    sampleSize: number;
    weeksCovered: number;
  };
}> {
  try {
    const thresholds = TASK_THRESHOLDS[taskType];
    const twoWeeksAgo = new Date();
    twoWeeksAgo.setDate(twoWeeksAgo.getDate() - thresholds.minWeeks * 7);

    // Get ML performance logs for this task
    const logs = await prisma.aIPerformanceLog.findMany({
      where: {
        taskType,
        provider: 'ML_HF',
        createdAt: {
          gte: twoWeeksAgo,
        },
      },
    });

    const sampleSize = logs.length;
    const errorRate =
      logs.filter(log => log.errorOccurred).length / (sampleSize || 1);
    const avgAccuracy =
      logs
        .filter(log => log.accuracy !== null)
        .reduce((sum, log) => sum + (log.accuracy ?? 0), 0) / (sampleSize || 1);

    // Calculate weeks covered
    const oldestLog = logs.reduce(
      (oldest, log) => (log.createdAt < oldest ? log.createdAt : oldest),
      new Date()
    );
    const weeksCovered =
      (Date.now() - oldestLog.getTime()) / (7 * 24 * 60 * 60 * 1000);

    const metrics = {
      accuracy: avgAccuracy,
      errorRate,
      sampleSize,
      weeksCovered,
    };

    // Check eligibility
    if (sampleSize < thresholds.minSampleSize) {
      return {
        eligible: false,
        reason: `Insufficient samples: ${sampleSize}/${thresholds.minSampleSize}`,
        metrics,
      };
    }

    if (weeksCovered < thresholds.minWeeks) {
      return {
        eligible: false,
        reason: `Insufficient time: ${weeksCovered.toFixed(1)}/${thresholds.minWeeks} weeks`,
        metrics,
      };
    }

    if (avgAccuracy < thresholds.minAccuracy) {
      return {
        eligible: false,
        reason: `Accuracy too low: ${(avgAccuracy * 100).toFixed(1)}%/${(thresholds.minAccuracy * 100).toFixed(1)}%`,
        metrics,
      };
    }

    if (errorRate > thresholds.maxErrorRate) {
      return {
        eligible: false,
        reason: `Error rate too high: ${(errorRate * 100).toFixed(1)}%/${(thresholds.maxErrorRate * 100).toFixed(1)}%`,
        metrics,
      };
    }

    return {
      eligible: true,
      reason: 'All thresholds met',
      metrics,
    };
  } catch (error) {
    logError('Failed to check migration eligibility', { error, taskType });
    return {
      eligible: false,
      reason: 'Error checking eligibility',
      metrics: {
        accuracy: 0,
        errorRate: 1,
        sampleSize: 0,
        weeksCovered: 0,
      },
    };
  }
}

/**
 * Initialize default app settings
 */
export async function initializeMLSettings(): Promise<void> {
  try {
    const defaultSettings = [
      {
        key: 'enable_ml',
        value: 'false',
        description:
          'Master switch for ML provider (default: false for safety)',
      },
      {
        key: 'ml_feature_security_scan',
        value: 'false',
        description: 'Use ML for security scans',
      },
      {
        key: 'ml_feature_threat_analysis',
        value: 'false',
        description: 'Use ML for threat analysis',
      },
      {
        key: 'ml_feature_api_generation',
        value: 'false',
        description: 'Use ML for API generation',
      },
      {
        key: 'ml_feature_vulnerability_detection',
        value: 'false',
        description: 'Use ML for vulnerability detection',
      },
      {
        key: 'ml_feature_code_review',
        value: 'false',
        description: 'Use ML for code review',
      },
      {
        key: 'ml_feature_compliance_check',
        value: 'false',
        description: 'Use ML for compliance checks',
      },
    ];

    for (const setting of defaultSettings) {
      await prisma.appSettings.upsert({
        where: { key: setting.key },
        update: {},
        create: setting,
      });
    }

    logInfo('ML settings initialized successfully');
  } catch (error) {
    logError('Failed to initialize ML settings', { error });
    throw error;
  }
}
