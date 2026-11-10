/**
 * DevFortress SDK — Unified Audit Trail (CL-M3)
 *
 * Merges internal and external closed-loop audit events into a single
 * timeline with consistent fields regardless of source.
 *
 * Fields: source ('internal' | 'external' | 'hybrid'), tier, latency_ms
 *
 * @packageDocumentation
 */

import type { ThreatSeverity } from './types';
import type { InternalCLDecision } from './internal-closed-loop-engine';

// ── Audit Entry Types ───────────────────────────────────────

export type AuditSource = 'internal' | 'external' | 'hybrid';

export interface UnifiedAuditEntry {
  /** Unique event identifier */
  eventId: string;
  /** When the event occurred */
  timestamp: number;
  /** Source of the decision */
  source: AuditSource;
  /** Which tier made the decision (1, 2, 3 for internal; 0 for external) */
  tier: 0 | 1 | 2 | 3;
  /** Decision outcome */
  decision: InternalCLDecision | 'webhook_response';
  /** Threat score (0-100) */
  score: number;
  /** Severity classification */
  severity: ThreatSeverity;
  /** Evaluation latency in milliseconds */
  latencyMs: number;
  /** Client IP address */
  ip: string;
  /** Request path */
  path: string;
  /** HTTP method */
  method: string;
  /** Matched rules or threat types */
  matchedRules: string[];
  /** User ID if authenticated */
  userId?: string | null;
  /** Agent ID for AI agent events */
  agentId?: string;
  /** Session ID */
  sessionId?: string | null;
  /** Whether the circuit breaker was in fallback mode */
  fallbackMode?: boolean;
  /** Additional metadata */
  meta?: Record<string, unknown>;
}

// ── Audit Trail Configuration ───────────────────────────────

export interface UnifiedAuditConfig {
  /** Maximum number of entries to retain. Default: 100_000 */
  maxEntries?: number;
  /** Callback invoked on each new audit entry (e.g., for external forwarding) */
  onEntry?: (entry: UnifiedAuditEntry) => void | Promise<void>;
  /** Enable debug logging */
  debug?: boolean;
}

// ── Unified Audit Trail ─────────────────────────────────────

export class UnifiedAuditTrail {
  private entries: UnifiedAuditEntry[] = [];
  private maxEntries: number;
  private onEntry?: UnifiedAuditConfig['onEntry'];
  private debug: boolean;

  // Counters for statistics
  private stats = {
    internalDecisions: 0,
    externalDecisions: 0,
    hybridDecisions: 0,
    fallbackEvents: 0,
    totalBlocks: 0,
    totalAllows: 0,
    totalRateLimits: 0,
    avgInternalLatencyMs: 0,
    avgExternalLatencyMs: 0,
    internalLatencySum: 0,
    externalLatencySum: 0,
  };

  constructor(config: UnifiedAuditConfig = {}) {
    this.maxEntries = config.maxEntries ?? 100_000;
    this.onEntry = config.onEntry;
    this.debug = config.debug ?? false;
  }

  // ── S27: Dedup window for hybrid mode (prevent double-counting) ──
  private recentEventIds = new Map<string, number>(); // eventId → timestamp
  private static readonly DEDUP_WINDOW_MS = 5_000; // 5 seconds

  /**
   * Record an audit entry from any source (internal, external, or hybrid).
   * S27: Includes dedup for hybrid mode — same eventId within 5s is merged, not duplicated.
   */
  record(entry: UnifiedAuditEntry): void {
    // ── S27: Dedup check — skip duplicate eventIds within window ──
    const existing = this.recentEventIds.get(entry.eventId);
    if (existing && Date.now() - existing < UnifiedAuditTrail.DEDUP_WINDOW_MS) {
      // Merge: update existing entry if external takes precedence over internal
      const idx = this.entries.findIndex(e => e.eventId === entry.eventId);
      if (
        idx >= 0 &&
        entry.source === 'external' &&
        this.entries[idx].source === 'internal'
      ) {
        // S27: External decision overrides internal (conflict resolution)
        this.entries[idx] = {
          ...this.entries[idx],
          ...entry,
          source: 'hybrid',
        };
        if (this.debug) {
          console.log(
            `[DF Audit] DEDUP: merged ${entry.eventId} (external overrides internal)`
          );
        }
      }
      return; // Skip duplicate
    }

    // Track for dedup
    this.recentEventIds.set(entry.eventId, Date.now());
    // Bounded cleanup of dedup map (evict entries older than window)
    if (this.recentEventIds.size > 10_000) {
      const cutoff = Date.now() - UnifiedAuditTrail.DEDUP_WINDOW_MS;
      for (const [id, ts] of this.recentEventIds) {
        if (ts < cutoff) this.recentEventIds.delete(id);
      }
    }

    // Bounded storage — evict oldest 10% when full
    if (this.entries.length >= this.maxEntries) {
      this.entries.splice(0, Math.floor(this.maxEntries * 0.1));
    }

    this.entries.push(entry);
    this.updateStats(entry);

    // Fire callback
    if (this.onEntry) {
      try {
        const result = this.onEntry(entry);
        if (result && typeof (result as Promise<void>).catch === 'function') {
          (result as Promise<void>).catch(() => {});
        }
      } catch {
        // Callback errors should not break the audit trail
      }
    }

    if (this.debug) {
      console.log(
        `[DF Audit] ${entry.source}:tier${entry.tier} ${entry.decision} score=${entry.score} ${entry.ip} ${entry.method} ${entry.path} (${entry.latencyMs}ms)`
      );
    }
  }

  /**
   * Query audit entries with filters.
   */
  query(filters?: {
    source?: AuditSource;
    decision?: string;
    ip?: string;
    userId?: string;
    agentId?: string;
    minScore?: number;
    since?: number;
    limit?: number;
  }): ReadonlyArray<UnifiedAuditEntry> {
    let result = this.entries;

    if (filters) {
      if (filters.source) {
        result = result.filter(e => e.source === filters.source);
      }
      if (filters.decision) {
        result = result.filter(e => e.decision === filters.decision);
      }
      if (filters.ip) {
        result = result.filter(e => e.ip === filters.ip);
      }
      if (filters.userId) {
        result = result.filter(e => e.userId === filters.userId);
      }
      if (filters.agentId) {
        result = result.filter(e => e.agentId === filters.agentId);
      }
      if (filters.minScore !== undefined) {
        result = result.filter(e => e.score >= filters.minScore!);
      }
      if (filters.since) {
        result = result.filter(e => e.timestamp >= filters.since!);
      }
    }

    const limit = filters?.limit ?? 100;
    return result.slice(-limit);
  }

  /**
   * Get aggregated statistics.
   */
  getStats(): {
    total: number;
    internalDecisions: number;
    externalDecisions: number;
    hybridDecisions: number;
    fallbackEvents: number;
    totalBlocks: number;
    totalAllows: number;
    totalRateLimits: number;
    avgInternalLatencyMs: number;
    avgExternalLatencyMs: number;
  } {
    return {
      total: this.entries.length,
      ...this.stats,
      avgInternalLatencyMs:
        this.stats.internalDecisions > 0
          ? Math.round(
              this.stats.internalLatencySum / this.stats.internalDecisions
            )
          : 0,
      avgExternalLatencyMs:
        this.stats.externalDecisions > 0
          ? Math.round(
              this.stats.externalLatencySum / this.stats.externalDecisions
            )
          : 0,
    };
  }

  /**
   * Get decision distribution for dashboard visualization.
   */
  getDecisionDistribution(): Record<string, number> {
    const dist: Record<string, number> = {};
    for (const entry of this.entries) {
      const key = `${entry.source}:${entry.decision}`;
      dist[key] = (dist[key] || 0) + 1;
    }
    return dist;
  }

  /**
   * Get latency histogram buckets.
   */
  getLatencyHistogram(): {
    under1ms: number;
    under5ms: number;
    under50ms: number;
    under200ms: number;
    under1s: number;
    over1s: number;
  } {
    const hist = {
      under1ms: 0,
      under5ms: 0,
      under50ms: 0,
      under200ms: 0,
      under1s: 0,
      over1s: 0,
    };

    for (const entry of this.entries) {
      if (entry.latencyMs < 1) hist.under1ms++;
      else if (entry.latencyMs < 5) hist.under5ms++;
      else if (entry.latencyMs < 50) hist.under50ms++;
      else if (entry.latencyMs < 200) hist.under200ms++;
      else if (entry.latencyMs < 1000) hist.under1s++;
      else hist.over1s++;
    }

    return hist;
  }

  /**
   * Export entries as JSON (for compliance/archival).
   */
  exportJSON(since?: number): string {
    const entries = since
      ? this.entries.filter(e => e.timestamp >= since)
      : this.entries;
    return JSON.stringify(entries, null, 2);
  }

  /**
   * Reset the audit trail (for testing).
   * @internal
   */
  _reset(): void {
    this.entries = [];
    this.stats = {
      internalDecisions: 0,
      externalDecisions: 0,
      hybridDecisions: 0,
      fallbackEvents: 0,
      totalBlocks: 0,
      totalAllows: 0,
      totalRateLimits: 0,
      avgInternalLatencyMs: 0,
      avgExternalLatencyMs: 0,
      internalLatencySum: 0,
      externalLatencySum: 0,
    };
  }

  private updateStats(entry: UnifiedAuditEntry): void {
    // Source counts
    if (entry.source === 'internal') {
      this.stats.internalDecisions++;
      this.stats.internalLatencySum += entry.latencyMs;
    } else if (entry.source === 'external') {
      this.stats.externalDecisions++;
      this.stats.externalLatencySum += entry.latencyMs;
    } else {
      this.stats.hybridDecisions++;
      // Assign to internal or external based on tier
      if (entry.tier > 0) {
        this.stats.internalLatencySum += entry.latencyMs;
      } else {
        this.stats.externalLatencySum += entry.latencyMs;
      }
    }

    // Fallback tracking
    if (entry.fallbackMode) {
      this.stats.fallbackEvents++;
    }

    // Decision counts
    if (entry.decision === 'block') {
      this.stats.totalBlocks++;
    } else if (entry.decision === 'allow') {
      this.stats.totalAllows++;
    } else if (entry.decision === 'rate_limit') {
      this.stats.totalRateLimits++;
    }
  }
}
