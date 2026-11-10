
import { OfflineQueue } from '../transport/offline-queue';

// L1: ECL unavailability fallback — ICL takes over when platform unreachable
export class EclFallbackManager {
  private eclHealthy = true;
  private readonly fallbackQueue = new OfflineQueue();
  private readonly healthCheckIntervalMs: number;

  constructor(healthCheckIntervalMs = 30000) {
    this.healthCheckIntervalMs = healthCheckIntervalMs;
    this.startHealthMonitor();
  }

  private startHealthMonitor(): void {
    setInterval(async () => {
      try {
        const res = await fetch(
          `${process.env.DEVFORTRESS_ENDPOINT ?? ''}/api/health`,
          {
            signal: AbortSignal.timeout(3000),
          }
        );
        this.eclHealthy = res.ok;
      } catch {
        this.eclHealthy = false;
      }
    }, this.healthCheckIntervalMs);
  }

  isEclHealthy(): boolean {
    return this.eclHealthy;
  }
  getMode(): 'ecl' | 'icl_fallback' {
    return this.eclHealthy ? 'ecl' : 'icl_fallback';
  }
}

// L2: Rule staleness — version checking with forced refresh
export class RuleVersionChecker {
  private localVersion = 0;
  private readonly refreshIntervalMs: number;

  constructor(refreshIntervalMs = 60000) {
    this.refreshIntervalMs = refreshIntervalMs;
  }

  async checkAndRefresh(
    fetchLatest: () => Promise<{ version: number; rules: unknown[] }>
  ): Promise<boolean> {
    const latest = await fetchLatest();
    if (latest.version > this.localVersion) {
      this.localVersion = latest.version;
      return true; // rules refreshed
    }
    return false;
  }
}

// L3: Reduce serialization latency — minimal payload transport
export function serializeEventMinimal(event: Record<string, unknown>): string {
  // Strip non-essential fields, use short keys
  return JSON.stringify({
    t: event.threatType,
    ip: event.sourceIp,
    s: event.subjectId,
    ts: event.timestamp,
    sv: event.severity,
    ep: event.endpoint,
  });
}

// L4: Memory budget enforcement
export class MemoryBudgetEnforcer {
  private readonly maxBytes: number;

  constructor(maxMb = 50) {
    this.maxBytes = maxMb * 1024 * 1024;
  }

  isWithinBudget(): boolean {
    if (typeof process !== 'undefined' && process.memoryUsage) {
      return process.memoryUsage().heapUsed < this.maxBytes;
    }
    return true; // browser environment — no check
  }

  getUsageMb(): number {
    if (typeof process !== 'undefined' && process.memoryUsage) {
      return Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
    }
    return 0;
  }
}

// L5: NTP-independent relative timing
export class RelativeTimer {
  private readonly startTime = Date.now();
  private readonly startHrTime =
    typeof process !== 'undefined' ? process.hrtime.bigint() : BigInt(0);

  getRelativeMs(): number {
    if (typeof process !== 'undefined') {
      return Number(process.hrtime.bigint() - this.startHrTime) / 1_000_000;
    }
    return Date.now() - this.startTime;
  }

  getTimestamp(): number {
    return this.startTime + this.getRelativeMs();
  }
}

// L6: At-least-once webhook delivery with idempotency
export class IdempotentWebhookDelivery {
  private readonly delivered = new Map<string, number>(); // idempotencyKey → timestamp

  isDuplicate(idempotencyKey: string): boolean {
    const ts = this.delivered.get(idempotencyKey);
    if (!ts) return false;
    // Purge keys older than 1 hour
    if (Date.now() - ts > 3600000) {
      this.delivered.delete(idempotencyKey);
      return false;
    }
    return true;
  }

  markDelivered(idempotencyKey: string): void {
    this.delivered.set(idempotencyKey, Date.now());
  }
}

// L7: Multi-instance SDK coordination (leader election stub)
// Full leader election requires distributed lock — stubbed with Redis SETNX pattern
export async function tryAcquireLeadership(
  instanceId: string,
  setFn: (key: string, value: string, ttl: number) => Promise<boolean>
): Promise<boolean> {
  return setFn('df:icl:leader', instanceId, 30); // 30s TTL
}

// L8: Configuration drift detection
export function computeConfigHash(config: Record<string, unknown>): string {
  const { createHash } = require('crypto');
  return createHash('sha256')
    .update(JSON.stringify(config, Object.keys(config).sort()))
    .digest('hex');
}

export function detectConfigDrift(
  localConfigHash: string,
  remoteConfigHash: string
): { drifted: boolean; details: string } {
  const drifted = localConfigHash !== remoteConfigHash;
  return {
    drifted,
    details: drifted
      ? `Config drift detected. Local: ${localConfigHash.slice(0, 8)}… Remote: ${remoteConfigHash.slice(0, 8)}…`
      : 'Config in sync',
  };
}
