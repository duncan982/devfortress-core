/**
 * Open-core stub — the real CrossCustomerThreatIntel (Patent Pending —
 * KIPI KE/P/2026/005973) is proprietary and not part of this
 * build. See open-core-strip.sh Op 14.
 *
 * Never wired into DevFortressCore itself (opt-in-only, confirmed by
 * grepping devfortress.ts for every symbol below before writing this).
 * contribute()/query() are local no-ops that always report "no match"
 * rather than fabricate cross-customer intelligence.
 */
export interface CrossCustomerConfig {
  platformEndpoint: string;
  apiKey: string;
  minCustomers?: number;
  aggregationWindowMs?: number;
  enabled?: boolean;
}

export interface ThreatSignal {
  fingerprint: string;
  threatType: string;
  ipHash: string;
  confidence: number;
  timestamp: number;
}

export interface CrossCustomerResult {
  matched: boolean;
  customerCount: number;
  aggregatedScore: number;
  recommendedAction: 'monitor' | 'challenge' | 'block';
  source: 'cross-customer';
}

export interface CrossCustomerStats {
  signalsContributed: number;
  signalsReceived: number;
  matchCount: number;
  lastSyncTimestamp: number;
}

export class CrossCustomerThreatIntel {
  constructor(_config: CrossCustomerConfig) {}

  async contribute(_signal: ThreatSignal): Promise<void> {}

  async query(
    _ipHash: string,
    _threatType: string
  ): Promise<CrossCustomerResult> {
    return {
      matched: false,
      customerCount: 0,
      aggregatedScore: 0,
      recommendedAction: 'monitor',
      source: 'cross-customer',
    };
  }

  getStats(): CrossCustomerStats {
    return {
      signalsContributed: 0,
      signalsReceived: 0,
      matchCount: 0,
      lastSyncTimestamp: 0,
    };
  }

  prune(): void {}
}
