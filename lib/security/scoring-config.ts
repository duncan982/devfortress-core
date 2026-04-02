/**
 * Threat Scoring Configuration (IP-S2)
 *
 * Post-authentication threshold reduction: logged-in users with
 * high internal confidence signals are MORE dangerous than clean-IP
 * pre-auth probes (credential-stuffing typically uses purchased accounts).
 *
 * Provides separate thresholds for pre-auth and post-auth events.
 */

// ── Scoring Thresholds ──────────────────────────────────────

export interface ScoringConfig {
  /** Threshold for pre-auth events (anonymous visitors). Default: 85 */
  criticalThreshold: number;
  /** Lower threshold for post-auth events (logged-in users). Default: 70 */
  postAuthThreshold: number;
  /** Threshold for high severity (non-critical). Default: 60 */
  highThreshold: number;
  /** Threshold for medium severity. Default: 40 */
  mediumThreshold: number;
}

const DEFAULT_CONFIG: ScoringConfig = {
  criticalThreshold: 85,
  postAuthThreshold: 70,
  highThreshold: 60,
  mediumThreshold: 40,
};

let activeConfig: ScoringConfig = { ...DEFAULT_CONFIG };

/**
 * Configure scoring thresholds.
 * Call this during app initialization to customize thresholds.
 */
export function configureScoringThresholds(
  config: Partial<ScoringConfig>
): void {
  activeConfig = { ...DEFAULT_CONFIG, ...config };
}

/**
 * Get the effective critical threshold based on authentication state.
 *
 * IP-S2: Use postAuthThreshold when the event has a user_id
 * (logged-in user = higher risk profile = lower threshold).
 */
export function getEffectiveCriticalThreshold(
  userId: string | null | undefined
): number {
  if (userId) {
    return activeConfig.postAuthThreshold;
  }
  return activeConfig.criticalThreshold;
}

/**
 * Classify a composite score into a severity level.
 * Uses post-auth threshold reduction (IP-S2) when userId is present.
 */
export function classifyThreatSeverity(
  compositeScore: number,
  userId?: string | null
): 'critical' | 'high' | 'medium' | 'low' {
  const criticalThreshold = getEffectiveCriticalThreshold(userId);

  if (compositeScore >= criticalThreshold) return 'critical';
  if (compositeScore >= activeConfig.highThreshold) return 'high';
  if (compositeScore >= activeConfig.mediumThreshold) return 'medium';
  return 'low';
}

/**
 * Get current active scoring configuration (for debugging/admin display).
 */
export function getScoringConfig(): Readonly<ScoringConfig> {
  return { ...activeConfig };
}
