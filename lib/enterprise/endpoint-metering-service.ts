/**
 * Endpoint Metering Service
 *
 * Tracks API endpoint usage for enterprise billing:
 * - Auto-registers endpoints from SDK observe() calls
 * - Normalises paths (strips UUIDs, numeric IDs)
 * - Counts distinct active endpoints per billing period
 * - Enforces tier-based limits with soft alerts at 80%
 * - Calculates overage charges
 */

import { logInfo, logWarn, logError } from '@core/lib/logger';

/* ─── Types ─── */

export interface EndpointRecord {
  id: string;
  orgId: string;
  method: string;
  path: string; // normalised
  rawPaths: string[]; // original paths (first 5 examples)
  firstSeen: string;
  lastSeen: string;
  requestCount: number;
  isActive: boolean; // had traffic in current billing period
}

export interface UsagePeriod {
  orgId: string;
  periodStart: string;
  periodEnd: string;
  activeEndpoints: number;
  includedEndpoints: number;
  overageEndpoints: number;
  overageCharge: number; // in cents
  alertSent: boolean;
}

export interface MeteringConfig {
  /** Included endpoints per tier */
  tierLimits: Record<string, number>;
  /** Cost per additional 10 endpoints (in cents) */
  overagePer10: number;
  /** Alert threshold (0.0 – 1.0, default 0.8) */
  alertThreshold: number;
}

export type EndpointEvent = {
  orgId: string;
  method: string;
  path: string;
  timestamp: string;
};

/* ─── Path normalisation ─── */

const UUID_RE =
  /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
const NUMERIC_ID_RE = /\/\d+(?=\/|$)/g;
const MONGO_ID_RE = /\/[0-9a-f]{24}(?=\/|$)/gi;

export function normalisePath(rawPath: string): string {
  return rawPath
    .replace(UUID_RE, ':id')
    .replace(MONGO_ID_RE, ':id')
    .replace(NUMERIC_ID_RE, '/:id')
    .replace(/\/+/g, '/')
    .replace(/\/$/, '')
    .toLowerCase();
}

/* ─── In-Memory Metering Store ─── */
// Production: replace with Supabase/Redis
const endpointStore = new Map<string, EndpointRecord>();
const usageStore = new Map<string, UsagePeriod>();

function endpointKey(orgId: string, method: string, path: string): string {
  return `${orgId}::${method}::${path}`;
}

function periodKey(orgId: string): string {
  const now = new Date();
  return `${orgId}::${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
}

/* ─── Service ─── */

export class EndpointMeteringService {
  private config: MeteringConfig;

  constructor(config?: Partial<MeteringConfig>) {
    this.config = {
      tierLimits: {
        starter: 5,
        pro: 25,
        enterprise_business: 200,
        enterprise: 500,
        enterprise_plus: Infinity,
      },
      overagePer10: 15000, // $150 per 10 endpoints
      alertThreshold: 0.8,
      ...config,
    };
    logInfo('EndpointMeteringService initialized', {
      tierLimits: this.config.tierLimits,
    });
  }

  /* ─── Register an endpoint observation ─── */
  recordEndpoint(event: EndpointEvent): EndpointRecord {
    const normalised = normalisePath(event.path);
    const key = endpointKey(event.orgId, event.method, normalised);

    const existing = endpointStore.get(key);
    if (existing) {
      existing.lastSeen = event.timestamp;
      existing.requestCount += 1;
      existing.isActive = true;
      if (
        existing.rawPaths.length < 5 &&
        !existing.rawPaths.includes(event.path)
      ) {
        existing.rawPaths.push(event.path);
      }
      endpointStore.set(key, existing);
      return existing;
    }

    const record: EndpointRecord = {
      id: `ep_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      orgId: event.orgId,
      method: event.method,
      path: normalised,
      rawPaths: [event.path],
      firstSeen: event.timestamp,
      lastSeen: event.timestamp,
      requestCount: 1,
      isActive: true,
    };
    endpointStore.set(key, record);
    logInfo('New endpoint registered', {
      orgId: event.orgId,
      method: event.method,
      path: normalised,
    });
    return record;
  }

  /* ─── Get active endpoint count for an org ─── */
  getActiveEndpoints(orgId: string): EndpointRecord[] {
    const results: EndpointRecord[] = [];
    for (const [, record] of endpointStore) {
      if (record.orgId === orgId && record.isActive) {
        results.push(record);
      }
    }
    return results;
  }

  /* ─── Get endpoint inventory ─── */
  getEndpointInventory(
    orgId: string,
    options?: { includeInactive?: boolean }
  ): EndpointRecord[] {
    const results: EndpointRecord[] = [];
    for (const [, record] of endpointStore) {
      if (record.orgId === orgId) {
        if (options?.includeInactive || record.isActive) {
          results.push(record);
        }
      }
    }
    return results.sort(
      (a, b) => new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime()
    );
  }

  /* ─── Calculate usage for billing period ─── */
  calculateUsage(orgId: string, tier: string): UsagePeriod {
    const active = this.getActiveEndpoints(orgId);
    const included = this.config.tierLimits[tier] ?? 0;
    const overage = Math.max(0, active.length - included);
    const overageBlocks = Math.ceil(overage / 10);
    const overageCharge = overageBlocks * this.config.overagePer10;

    const now = new Date();
    const periodStart = new Date(
      now.getFullYear(),
      now.getMonth(),
      1
    ).toISOString();
    const periodEnd = new Date(
      now.getFullYear(),
      now.getMonth() + 1,
      0
    ).toISOString();

    const pk = periodKey(orgId);
    const existingPeriod = usageStore.get(pk);

    const period: UsagePeriod = {
      orgId,
      periodStart,
      periodEnd,
      activeEndpoints: active.length,
      includedEndpoints: included === Infinity ? -1 : included,
      overageEndpoints: overage,
      overageCharge,
      alertSent: existingPeriod?.alertSent ?? false,
    };

    // Check if alert threshold is reached
    if (
      included !== Infinity &&
      active.length >= included * this.config.alertThreshold &&
      !period.alertSent
    ) {
      period.alertSent = true;
      logWarn('Endpoint usage approaching limit', {
        orgId,
        tier,
        active: active.length,
        included,
        threshold: `${this.config.alertThreshold * 100}%`,
      });
    }

    usageStore.set(pk, period);
    return period;
  }

  /* ─── Check if org is within limits ─── */
  isWithinLimits(orgId: string, tier: string): boolean {
    const active = this.getActiveEndpoints(orgId);
    const limit = this.config.tierLimits[tier] ?? 0;
    return limit === Infinity || active.length <= limit;
  }

  /* ─── Export inventory as CSV ─── */
  exportInventoryCSV(orgId: string): string {
    const records = this.getEndpointInventory(orgId, {
      includeInactive: true,
    });
    const header = 'Method,Path,First Seen,Last Seen,Request Count,Active';
    const rows = records.map(
      r =>
        `${r.method},${r.path},${r.firstSeen},${r.lastSeen},${r.requestCount},${r.isActive}`
    );
    return [header, ...rows].join('\n');
  }

  /* ─── Reset period (for testing / month rollover) ─── */
  resetPeriod(orgId: string): void {
    for (const [key, record] of endpointStore) {
      if (record.orgId === orgId) {
        record.isActive = false;
        record.requestCount = 0;
        endpointStore.set(key, record);
      }
    }
    const pk = periodKey(orgId);
    usageStore.delete(pk);
    logInfo('Metering period reset', { orgId });
  }

  /* ─── Stats ─── */
  getStats(): {
    totalEndpoints: number;
    totalOrgs: number;
    activePeriods: number;
  } {
    const orgs = new Set<string>();
    for (const [, r] of endpointStore) orgs.add(r.orgId);
    return {
      totalEndpoints: endpointStore.size,
      totalOrgs: orgs.size,
      activePeriods: usageStore.size,
    };
  }
}

/* ─── Singleton ─── */
export const endpointMeteringService = new EndpointMeteringService();
