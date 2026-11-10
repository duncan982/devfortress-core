/**
 * Open-core stub — the real air-gap offline classifier/rule-engine/audit-
 * logger bundle is a "pending review" post-MVP feature excluded from this
 * build, not patent-boundary content, but it is still proprietary source
 * excluded the same way. See open-core-strip.sh Op 14.
 *
 * Never wired into DevFortressCore itself (opt-in-only, confirmed by
 * grepping devfortress.ts for every symbol below before writing this), so
 * this fails loud on use rather than silently no-op protecting traffic.
 */
export interface AirGapConfig {
  modelPath: string;
  ruleSetPath: string;
  auditLogPath: string;
  threatIntelPath?: string;
}

const NOT_AVAILABLE = 'Air-gap mode is not available in the open-core build';

export class DevFortressAirGap {
  constructor(_config: AirGapConfig) {}

  async init(): Promise<void> {
    throw new Error(NOT_AVAILABLE);
  }

  async protect(
    _requestData: unknown
  ): Promise<{ allowed: boolean; reason?: string }> {
    throw new Error(NOT_AVAILABLE);
  }

  async ingest(_event: unknown): Promise<void> {
    throw new Error(NOT_AVAILABLE);
  }

  async classify(
    _features: Float32Array
  ): Promise<{ score: number; label: string }> {
    throw new Error(NOT_AVAILABLE);
  }
}
