/**
 * AI-Driven Anomaly Detection Service
 * Uses ML algorithms to detect patterns in logs, traffic, and user behavior
 */

import { logInfo, logError, logWarn } from '../logger';
import { prisma } from '../prisma';
import { ThreatSeverity } from '@prisma/client';

// Anomaly types
export enum AnomalyType {
  TRAFFIC_SPIKE = 'TRAFFIC_SPIKE',
  UNUSUAL_PATTERN = 'UNUSUAL_PATTERN',
  HONEYPOT_TARGETING = 'HONEYPOT_TARGETING',
  SUSPICIOUS_IP = 'SUSPICIOUS_IP',
  RAPID_REQUESTS = 'RAPID_REQUESTS',
  UNUSUAL_PAYLOAD = 'UNUSUAL_PAYLOAD',
}

export interface AnomalyDetectionResult {
  isAnomaly: boolean;
  type?: AnomalyType;
  confidence: number;
  severity: ThreatSeverity;
  explanation: string;
  recommendedAction?: string;
  metadata?: Record<string, unknown>;
}

export interface TrafficPattern {
  sourceIp: string;
  requestCount: number;
  timeWindow: number; // minutes
  uniqueEndpoints: number;
  payloadSizes: number[];
  userAgents: string[];
}

export interface AnomalyThresholds {
  trafficSpikeMultiplier: number; // e.g., 3x average = spike
  rapidRequestsPerMinute: number; // e.g., 100 requests/min
  uniqueEndpointThreshold: number; // e.g., >10 endpoints = scanning
  payloadSizeStdDev: number; // standard deviations from mean
  confidenceThreshold: number; // minimum confidence to report
}

// Default thresholds (can be tuned based on data)
const DEFAULT_THRESHOLDS: AnomalyThresholds = {
  trafficSpikeMultiplier: 3.0,
  rapidRequestsPerMinute: 100,
  uniqueEndpointThreshold: 10,
  payloadSizeStdDev: 2.5,
  confidenceThreshold: 0.7,
};

export class AnomalyDetectorService {
  private thresholds: AnomalyThresholds;
  private trainingData: Map<string, number[]> = new Map();

  constructor(thresholds?: Partial<AnomalyThresholds>) {
    this.thresholds = { ...DEFAULT_THRESHOLDS, ...thresholds };
  }

  private isDatabaseConfigured(): boolean {
    return Boolean(process.env.DATABASE_URL);
  }

  /**
   * Analyze traffic pattern for anomalies
   */
  async analyzeTrafficPattern(
    pattern: TrafficPattern,
    honeypotId: string
  ): Promise<AnomalyDetectionResult> {
    try {
      logInfo('Analyzing traffic pattern for anomalies', {
        sourceIp: pattern.sourceIp,
        honeypotId,
      });

      // Get baseline statistics for this honeypot
      const baseline = await this.getBaselineStatistics(honeypotId);

      // Check for rapid requests
      if (pattern.requestCount > this.thresholds.rapidRequestsPerMinute) {
        return this.createAnomalyResult(
          AnomalyType.RAPID_REQUESTS,
          0.95,
          ThreatSeverity.HIGH,
          `Detected ${pattern.requestCount} requests in ${pattern.timeWindow} minutes from ${pattern.sourceIp}`,
          'Implement rate limiting or block IP temporarily'
        );
      }

      // Check for scanning behavior (many unique endpoints)
      if (pattern.uniqueEndpoints >= this.thresholds.uniqueEndpointThreshold) {
        return this.createAnomalyResult(
          AnomalyType.UNUSUAL_PATTERN,
          0.9,
          ThreatSeverity.MEDIUM,
          `IP ${pattern.sourceIp} accessed ${pattern.uniqueEndpoints} unique endpoints, indicating scanning behavior`,
          'Monitor IP and consider blocking if behavior continues'
        );
      }

      // Check for traffic spike compared to baseline
      if (baseline.avgRequestsPerMinute > 0) {
        const currentRate = pattern.requestCount / pattern.timeWindow;
        const spikeRatio = currentRate / baseline.avgRequestsPerMinute;

        if (spikeRatio >= this.thresholds.trafficSpikeMultiplier) {
          return this.createAnomalyResult(
            AnomalyType.TRAFFIC_SPIKE,
            Math.min(0.8 + spikeRatio / 10, 0.99),
            ThreatSeverity.MEDIUM,
            `Traffic spike detected: ${spikeRatio.toFixed(2)}x normal rate from ${pattern.sourceIp}`,
            'Investigate source and verify legitimacy'
          );
        }
      }

      // Check for unusual payload sizes using statistical analysis
      if (pattern.payloadSizes.length > 0) {
        const payloadAnomaly = this.detectPayloadAnomalies(
          pattern.payloadSizes,
          baseline.avgPayloadSize,
          baseline.stdDevPayloadSize
        );

        if (payloadAnomaly) {
          return payloadAnomaly;
        }
      }

      // Check for honeypot targeting patterns
      const targetingScore = await this.calculateHoneypotTargetingScore(
        pattern,
        honeypotId
      );

      if (targetingScore > 0.7) {
        return this.createAnomalyResult(
          AnomalyType.HONEYPOT_TARGETING,
          targetingScore,
          ThreatSeverity.CRITICAL,
          `Detected potential honeypot targeting from ${pattern.sourceIp} (score: ${targetingScore.toFixed(2)})`,
          'Immediate investigation required - potential linkage attack'
        );
      }

      const suspiciousAgents = pattern.userAgents.filter(ua =>
        /bot|crawler|scanner|curl|wget|python|nikto|sqlmap/i.test(ua)
      );

      if (suspiciousAgents.length > 0) {
        const confidence = Math.min(0.7 + suspiciousAgents.length * 0.05, 0.9);
        const severity =
          pattern.uniqueEndpoints >= 5 || pattern.requestCount > 10
            ? ThreatSeverity.MEDIUM
            : ThreatSeverity.LOW;

        return this.createAnomalyResult(
          AnomalyType.UNUSUAL_PATTERN,
          confidence,
          severity,
          `Suspicious user agents detected from ${pattern.sourceIp}: ${suspiciousAgents.join(', ')}`,
          'Investigate automation patterns and consider blocking the source'
        );
      }

      // No anomalies detected
      return {
        isAnomaly: false,
        confidence: 0.5,
        severity: ThreatSeverity.LOW,
        explanation: 'Traffic pattern appears normal',
      };
    } catch (error) {
      logError('Error analyzing traffic pattern', { error, pattern });
      throw error;
    }
  }

  /**
   * Get baseline statistics for a honeypot
   */
  private async getBaselineStatistics(honeypotId: string) {
    const oneWeekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

    if (!this.isDatabaseConfigured()) {
      logWarn(
        'Database not configured for baseline statistics; using defaults',
        {
          honeypotId,
        }
      );
      return {
        avgRequestsPerMinute: 0,
        avgPayloadSize: 0,
        stdDevPayloadSize: 0,
      };
    }

    try {
      const events = await prisma.threatEvent.findMany({
        where: {
          honeypotId,
          detectedAt: { gte: oneWeekAgo },
          isFalsePositive: false,
        },
        select: {
          detectedAt: true,
          payload: true,
        },
      });

      if (events.length === 0) {
        return {
          avgRequestsPerMinute: 0,
          avgPayloadSize: 0,
          stdDevPayloadSize: 0,
        };
      }

      // Calculate requests per minute
      const timeRangeMinutes =
        (Date.now() - oneWeekAgo.getTime()) / (1000 * 60);
      const avgRequestsPerMinute = events.length / timeRangeMinutes;

      // Calculate payload size statistics
      const payloadSizes = events
        .map(e => {
          if (!e.payload) return 0;
          return JSON.stringify(e.payload).length;
        })
        .filter(size => size > 0);

      const avgPayloadSize =
        payloadSizes.length > 0
          ? payloadSizes.reduce((a, b) => a + b, 0) / payloadSizes.length
          : 0;

      const stdDevPayloadSize = this.calculateStdDev(
        payloadSizes,
        avgPayloadSize
      );

      return {
        avgRequestsPerMinute,
        avgPayloadSize,
        stdDevPayloadSize,
      };
    } catch (error) {
      logWarn('Failed to retrieve baseline statistics; using defaults', {
        honeypotId,
        error: error instanceof Error ? error.message : String(error),
      });
      return {
        avgRequestsPerMinute: 0,
        avgPayloadSize: 0,
        stdDevPayloadSize: 0,
      };
    }
  }

  /**
   * Detect anomalies in payload sizes
   */
  private detectPayloadAnomalies(
    sizes: number[],
    baseline: number,
    stdDev: number
  ): AnomalyDetectionResult | null {
    if (baseline === 0 || stdDev === 0) return null;

    const avgSize = sizes.reduce((a, b) => a + b, 0) / sizes.length;
    const zScore = Math.abs((avgSize - baseline) / stdDev);

    if (zScore > this.thresholds.payloadSizeStdDev) {
      return this.createAnomalyResult(
        AnomalyType.UNUSUAL_PAYLOAD,
        Math.min(0.7 + zScore / 10, 0.95),
        ThreatSeverity.MEDIUM,
        `Unusual payload sizes detected (${zScore.toFixed(2)} standard deviations from baseline)`,
        'Investigate payload contents for malicious patterns'
      );
    }

    return null;
  }

  /**
   * Calculate honeypot targeting score based on multiple signals
   */
  private async calculateHoneypotTargetingScore(
    pattern: TrafficPattern,
    honeypotId: string
  ): Promise<number> {
    let score = 0;
    let ipHoneypotsCount = 0;
    let uniqueTagCount = 0;

    if (this.isDatabaseConfigured()) {
      try {
        const ipHoneypots = await prisma.threatEvent.findMany({
          where: {
            sourceIp: pattern.sourceIp,
            detectedAt: { gte: new Date(Date.now() - 24 * 60 * 60 * 1000) },
          },
          distinct: ['honeypotId'],
          select: { honeypotId: true },
        });

        ipHoneypotsCount = ipHoneypots.length;

        const recentEvents = await prisma.threatEvent.findMany({
          where: {
            honeypotId,
            sourceIp: pattern.sourceIp,
            detectedAt: { gte: new Date(Date.now() - 60 * 60 * 1000) },
          },
          select: { tags: true },
        });

        const allTags = recentEvents.flatMap(e => e.tags ?? []);
        uniqueTagCount = new Set(allTags).size;
      } catch (error) {
        logWarn(
          'Unable to query historical threat events; using heuristic targeting score',
          {
            honeypotId,
            sourceIp: pattern.sourceIp,
            error: error instanceof Error ? error.message : String(error),
          }
        );
      }
    } else {
      logWarn(
        'Database not configured for honeypot targeting analysis; using heuristic scoring',
        {
          honeypotId,
          sourceIp: pattern.sourceIp,
        }
      );
    }

    if (ipHoneypotsCount > 3) {
      score += 0.4;
    } else if (ipHoneypotsCount > 1) {
      score += 0.2;
    }

    const suspiciousAgents = pattern.userAgents.filter(ua =>
      /bot|crawler|scanner|curl|wget|python|nikto|sqlmap/i.test(ua)
    );

    if (suspiciousAgents.length > 0) {
      score += 0.3;
    }

    if (pattern.uniqueEndpoints > 5) {
      score += 0.2;
    }

    if (uniqueTagCount > 3) {
      score += 0.2;
    }

    return Math.min(score, 1.0);
  }

  /**
   * Calculate standard deviation
   */
  private calculateStdDev(values: number[], mean: number): number {
    if (values.length === 0) return 0;

    const squareDiffs = values.map(value => Math.pow(value - mean, 2));
    const avgSquareDiff =
      squareDiffs.reduce((a, b) => a + b, 0) / values.length;

    return Math.sqrt(avgSquareDiff);
  }

  /**
   * Create anomaly result object
   */
  private createAnomalyResult(
    type: AnomalyType,
    confidence: number,
    severity: ThreatSeverity,
    explanation: string,
    recommendedAction?: string
  ): AnomalyDetectionResult {
    return {
      isAnomaly: true,
      type,
      confidence,
      severity,
      explanation,
      recommendedAction,
    };
  }

  /**
   * Store anomaly for model training
   */
  async storeAnomalyForTraining(
    anomaly: AnomalyDetectionResult,
    pattern: TrafficPattern,
    honeypotId: string
  ): Promise<void> {
    try {
      if (!this.isDatabaseConfigured()) {
        logWarn(
          'Skipping anomaly training data storage; database not configured',
          {
            honeypotId,
          }
        );
        return;
      }

       
      const prismaAny = prisma as any;
      await prismaAny.anomalyTrainingData.create({
        data: {
          honeypotId,
          sourceIp: pattern.sourceIp,
          anomalyType: anomaly.type || AnomalyType.UNUSUAL_PATTERN,
          confidence: anomaly.confidence,
          severity: anomaly.severity,
          features: {
            requestCount: pattern.requestCount,
            timeWindow: pattern.timeWindow,
            uniqueEndpoints: pattern.uniqueEndpoints,
            avgPayloadSize:
              pattern.payloadSizes.length > 0
                ? pattern.payloadSizes.reduce((a, b) => a + b, 0) /
                  pattern.payloadSizes.length
                : 0,
            userAgentCount: pattern.userAgents.length,
          },
          detectedAt: new Date(),
          validated: null, // Will be manually validated later
        },
      });

      logInfo('Stored anomaly data for training', {
        type: anomaly.type,
        honeypotId,
      });
    } catch (error) {
      logError('Error storing anomaly training data', { error });
    }
  }

  /**
   * Train/update model with accumulated data
   * This is a simplified version - in production, use actual ML libraries
   */
  async trainModel(honeypotId?: string): Promise<{
    success: boolean;
    metrics?: { accuracy: number; falsePositiveRate: number };
  }> {
    try {
      logInfo('Starting anomaly detection model training', { honeypotId });

      if (!this.isDatabaseConfigured()) {
        logWarn('Skipping model training; database not configured', {
          honeypotId,
        });
        return { success: false };
      }

      // Fetch validated training data
       
      const prismaAny = prisma as any;
      const trainingData = await prismaAny.anomalyTrainingData.findMany({
        where: {
          ...(honeypotId && { honeypotId }),
          validated: { not: null },
        },
        orderBy: { detectedAt: 'desc' },
        take: 10000, // Limit to recent data
      });

      if (trainingData.length < 100) {
        logWarn('Insufficient training data', {
          count: trainingData.length,
          required: 100,
        });
        
        // For testing/development, allow training with smaller datasets if we have at least 10 samples
        if (trainingData.length >= 10) {
          logInfo('Using reduced dataset for development/testing', {
            count: trainingData.length,
          });
        } else {
          return {
            success: false,
          };
        }
      }

      // Calculate accuracy metrics from validated data
      const validatedCorrect = trainingData.filter(
        (d: { validated: boolean | null }) => d.validated === true
      );
      const accuracy = validatedCorrect.length / trainingData.length;

      const falsePositives = trainingData.filter(
        (d: { validated: boolean | null; confidence: number }) =>
          d.validated === false && d.confidence > 0.7
      );
      const falsePositiveRate = falsePositives.length / trainingData.length;

      // Update thresholds based on performance
      if (falsePositiveRate > 0.05) {
        // If too many false positives, increase confidence threshold
        this.thresholds.confidenceThreshold = Math.min(
          this.thresholds.confidenceThreshold + 0.05,
          0.9
        );
        logInfo('Adjusted confidence threshold due to false positives', {
          newThreshold: this.thresholds.confidenceThreshold,
        });
      }

      logInfo('Model training completed', {
        accuracy,
        falsePositiveRate,
        dataPoints: trainingData.length,
      });

      return {
        success: true,
        metrics: {
          accuracy,
          falsePositiveRate,
        },
      };
    } catch (error) {
      logError('Error training anomaly detection model', { error });
      return { success: false };
    }
  }
}

// Singleton instance
export const anomalyDetector = new AnomalyDetectorService();
