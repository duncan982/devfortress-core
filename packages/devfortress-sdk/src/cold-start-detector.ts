/**
 * Open-core stub — the real ColdStartDetector (behavioral baseline /
 * population-comparator anomaly detection, Invention A1) is proprietary and
 * not part of this build. See open-core-strip.sh Op 14.
 *
 * recordObservation() is a no-op and assess() always reports
 * suspicious: false, so DevFortressCore's observe() never flags traffic on
 * a signal this build cannot actually evaluate.
 */

export interface ColdStartConfig {
  minSessionsForBaseline?: number;
  cvStabilityThreshold?: number;
  learningAlpha?: number;
  stableAlpha?: number;
  populationZScoreThreshold?: number;
  maxEntities?: number;
  featureDimensions?: number;
}

export interface BehavioralFeatureVector {
  avgCallsPerSession: number;
  endpointEntropy: number;
  avgRequestBytes: number;
  avgLatencyMs: number;
  avgSessionDurationMs: number;
  uniqueEndpoints: number;
  errorRate: number;
  timeOfDayBias: number;
  avgResponseBodyBytes: number;
}

export interface BaselineQuality {
  cvPerFeature: number[];
  maxCV: number;
  isStable: boolean;
  sessionCount: number;
  currentAlpha: number;
  phase: 'cold_start' | 'learning' | 'stable';
}

export interface ColdStartDetectionResult {
  entityId: string;
  suspicious: boolean;
  method: 'population_comparator' | 'individual_baseline' | 'hybrid';
  zScore: number;
  anomalousFeatures: string[];
  quality: BaselineQuality;
  confidence: number;
  detectedAt: number;
}

export class ColdStartDetector {
  constructor(_config: ColdStartConfig = {}) {}

  recordObservation(
    _entityId: string,
    _features: BehavioralFeatureVector
  ): void {}

  assess(
    entityId: string,
    _features: BehavioralFeatureVector
  ): ColdStartDetectionResult {
    return {
      entityId,
      suspicious: false,
      method: 'population_comparator',
      zScore: 0,
      anomalousFeatures: [],
      quality: {
        cvPerFeature: [],
        maxCV: 0,
        isStable: false,
        sessionCount: 0,
        currentAlpha: 0,
        phase: 'cold_start',
      },
      confidence: 0,
      detectedAt: Date.now(),
    };
  }
}
