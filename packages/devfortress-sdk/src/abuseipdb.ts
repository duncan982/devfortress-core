/**
 * Open-core stub — the real AbuseIPDB trade-secret composite-scoring
 * integration is proprietary and not part of this build. See
 * open-core-strip.sh Op 14.
 *
 * checkIP/reportIP/syncBlacklist throw rather than fabricate external
 * reputation data (this feature is simply unavailable, not safe to fake).
 * scoreThreat/getCachedScore/getAbuseIPDBRateLimitStatus are side-effect
 * free in the real module too, so they return a neutral, honestly-zeroed
 * result instead of throwing.
 */
import type {
  AbuseIPDBCheckResult,
  CompositeScoreResult,
  ThreatSeverity,
} from './types';

const NOT_AVAILABLE =
  'AbuseIPDB integration is not available in the open-core build';

export function getAbuseIPDBRateLimitStatus(): {
  checks: { used: number; limit: number };
  reports: { used: number; limit: number };
  blacklistSyncs: { used: number; limit: number };
  windowResetMs: number;
} {
  return {
    checks: { used: 0, limit: 0 },
    reports: { used: 0, limit: 0 },
    blacklistSyncs: { used: 0, limit: 0 },
    windowResetMs: 0,
  };
}

export async function checkIP(
  _ip: string,
  _apiKey: string
): Promise<AbuseIPDBCheckResult> {
  throw new Error(NOT_AVAILABLE);
}

export async function reportIP(
  _ip: string,
  _categories: number[],
  _comment: string,
  _apiKey: string
): Promise<{ data: { abuseConfidenceScore: number } }> {
  throw new Error(NOT_AVAILABLE);
}

export async function syncBlacklist(
  _apiKey: string,
  _confidenceMinimum: number = 90
): Promise<number> {
  throw new Error(NOT_AVAILABLE);
}

export async function scoreThreat(
  _ip: string,
  devFortressConfidence: number,
  _apiKey?: string
): Promise<CompositeScoreResult> {
  // No AbuseIPDB component available in this build — composite score is
  // the DevFortress signal alone (same 0.6 weight the real module applies
  // to it, with the AbuseIPDB 0.4 term honestly zeroed rather than faked).
  const score = Math.min(Math.round(devFortressConfidence * 100 * 0.6), 100);
  const severity: ThreatSeverity =
    score >= 85 ? 'critical' : score >= 60 ? 'high' : score >= 35 ? 'medium' : 'low';
  return {
    score,
    severity,
    abuseScore: 0,
    isTor: false,
    isDatacenter: false,
    distinctUsers: 0,
    fromCache: false,
  };
}

export function getCachedScore(_ip: string): number | null {
  return null;
}
