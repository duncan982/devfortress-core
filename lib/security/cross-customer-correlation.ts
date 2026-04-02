/**
 * Cross-Customer Velocity & Cross-Application Event Correlation (IP-S3 + IP-S4)
 *
 * IP-S3: Maintains per-IP velocity tracking across all customer applications.
 *        If the same IP triggers critical events across ≥3 distinct apps in 1 hour,
 *        it is added to the cross-customer blocklist.
 *
 * IP-S4: Maintains per-IP cross-application event correlation.
 *        If ≥2 distinct apps report high-confidence events within 60 seconds,
 *        a platform-level incident is declared and webhooks fire to ALL affected apps.
 *
 * Uses in-memory storage with optional Redis backing.
 * In production, this module runs on the platform (DevFortress server-side),
 * NOT in the client SDK.
 */

import { logInfo, logWarn, logError } from '@core/lib/logger';

// ── Types ───────────────────────────────────────────────────

export interface VelocityEvent {
  ip: string;
  appId: string;
  eventId: string;
  timestamp: number;
}

export interface PlatformIncident {
  incidentId: string;
  type: 'cross_customer_velocity' | 'cross_application';
  ip: string;
  affectedAppIds: string[];
  eventIds: string[];
  detectedAt: number;
  severity: 'critical';
}

export type IncidentHandler = (
  incident: PlatformIncident
) => Promise<void> | void;

// ── In-Memory Velocity Tracker (IP-S3) ──────────────────────

const velocityMap = new Map<string, VelocityEvent[]>();
const VELOCITY_WINDOW_MS = 60 * 60 * 1000; // 1 hour
const VELOCITY_THRESHOLD = 3; // distinct app_ids

// ── In-Memory Cross-App Tracker (IP-S4) ─────────────────────

const crossAppMap = new Map<string, VelocityEvent[]>();
const CROSS_APP_WINDOW_MS = 60 * 1000; // 60 seconds
const CROSS_APP_THRESHOLD = 2; // distinct app_ids

// ── Cross-Customer Blocklist ────────────────────────────────

const crossCustomerBlocklist = new Map<
  string,
  { reason: string; addedAt: number; expiresAt: number }
>();
const BLOCKLIST_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours

// ── Incident Handlers ───────────────────────────────────────

const incidentHandlers: IncidentHandler[] = [];

/**
 * Register a handler for platform-level incidents.
 * Handlers are called when cross-customer or cross-application incidents are detected.
 */
export function onPlatformIncident(handler: IncidentHandler): void {
  incidentHandlers.push(handler);
}

// ── Public API ──────────────────────────────────────────────

/**
 * Record a critical event for velocity tracking (IP-S3) and
 * cross-application correlation (IP-S4).
 *
 * Called from the event ingestion pipeline on the platform side.
 */
export async function recordCriticalEvent(event: VelocityEvent): Promise<{
  velocityBlocked: boolean;
  platformIncident: PlatformIncident | null;
}> {
  const { ip, appId, eventId, timestamp } = event;
  let velocityBlocked = false;
  let platformIncident: PlatformIncident | null = null;

  // ── IP-S3: Cross-Customer Velocity ──────────────────────

  const velocityKey = ip;
  if (!velocityMap.has(velocityKey)) {
    velocityMap.set(velocityKey, []);
  }
  const velocityEvents = velocityMap.get(velocityKey)!;

  // Add event and trim old entries
  velocityEvents.push(event);
  const velocityCutoff = timestamp - VELOCITY_WINDOW_MS;
  const trimmed = velocityEvents.filter(e => e.timestamp > velocityCutoff);
  velocityMap.set(velocityKey, trimmed);

  // Count distinct app_ids in window
  const distinctAppsVelocity = new Set(trimmed.map(e => e.appId));
  if (distinctAppsVelocity.size >= VELOCITY_THRESHOLD) {
    // Add to cross-customer blocklist
    if (!crossCustomerBlocklist.has(ip)) {
      crossCustomerBlocklist.set(ip, {
        reason: `cross_customer_velocity: ${distinctAppsVelocity.size} apps in 1h`,
        addedAt: timestamp,
        expiresAt: timestamp + BLOCKLIST_TTL_MS,
      });

      velocityBlocked = true;

      const incident: PlatformIncident = {
        incidentId: `vi_${Date.now()}_${ip.replace(/\./g, '_')}`,
        type: 'cross_customer_velocity',
        ip,
        affectedAppIds: Array.from(distinctAppsVelocity),
        eventIds: trimmed.map(e => e.eventId),
        detectedAt: timestamp,
        severity: 'critical',
      };

      platformIncident = incident;
      logWarn('[DF] Cross-customer velocity threshold reached', {
        ip,
        distinctApps: distinctAppsVelocity.size,
        events: trimmed.length,
      });

      // Fire incident handlers
      for (const handler of incidentHandlers) {
        try {
          await handler(incident);
        } catch (err) {
          logError('[DF] Incident handler error', {
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }
    }
  }

  // ── IP-S4: Cross-Application Correlation ────────────────

  if (!crossAppMap.has(ip)) {
    crossAppMap.set(ip, []);
  }
  const crossAppEvents = crossAppMap.get(ip)!;

  crossAppEvents.push(event);
  const crossAppCutoff = timestamp - CROSS_APP_WINDOW_MS;
  const crossAppTrimmed = crossAppEvents.filter(
    e => e.timestamp > crossAppCutoff
  );
  crossAppMap.set(ip, crossAppTrimmed);

  const distinctAppsCross = new Set(crossAppTrimmed.map(e => e.appId));
  if (distinctAppsCross.size >= CROSS_APP_THRESHOLD && !platformIncident) {
    const incident: PlatformIncident = {
      incidentId: `xapp_${Date.now()}_${ip.replace(/\./g, '_')}`,
      type: 'cross_application',
      ip,
      affectedAppIds: Array.from(distinctAppsCross),
      eventIds: crossAppTrimmed.map(e => e.eventId),
      detectedAt: timestamp,
      severity: 'critical',
    };

    platformIncident = incident;

    logInfo('[DF] Cross-application event correlation detected', {
      ip,
      distinctApps: distinctAppsCross.size,
      window: '60s',
    });

    for (const handler of incidentHandlers) {
      try {
        await handler(incident);
      } catch (err) {
        logError('[DF] Incident handler error', {
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }
  }

  return { velocityBlocked, platformIncident };
}

/**
 * Check if an IP is on the cross-customer blocklist.
 */
export function isOnCrossCustomerBlocklist(ip: string): boolean {
  const entry = crossCustomerBlocklist.get(ip);
  if (!entry) return false;
  if (Date.now() > entry.expiresAt) {
    crossCustomerBlocklist.delete(ip);
    return false;
  }
  return true;
}

/**
 * Get all IPs on the cross-customer blocklist (for sync to SDK instances).
 */
export function getCrossCustomerBlocklist(): Array<{
  ip: string;
  reason: string;
  addedAt: number;
}> {
  const now = Date.now();
  const result: Array<{ ip: string; reason: string; addedAt: number }> = [];

  for (const [ip, entry] of crossCustomerBlocklist.entries()) {
    if (now > entry.expiresAt) {
      crossCustomerBlocklist.delete(ip);
      continue;
    }
    result.push({ ip, reason: entry.reason, addedAt: entry.addedAt });
  }

  return result;
}

/**
 * Clean up expired entries. Call periodically (e.g. every 5 minutes).
 */
export function cleanupExpiredEntries(): void {
  const now = Date.now();

  // Clean velocity map (remove events older than 1 hour)
  for (const [ip, events] of velocityMap.entries()) {
    const valid = events.filter(e => e.timestamp > now - VELOCITY_WINDOW_MS);
    if (valid.length === 0) {
      velocityMap.delete(ip);
    } else {
      velocityMap.set(ip, valid);
    }
  }

  // Clean cross-app map (remove events older than 60s)
  for (const [ip, events] of crossAppMap.entries()) {
    const valid = events.filter(e => e.timestamp > now - CROSS_APP_WINDOW_MS);
    if (valid.length === 0) {
      crossAppMap.delete(ip);
    } else {
      crossAppMap.set(ip, valid);
    }
  }

  // Clean blocklist (remove expired)
  for (const [ip, entry] of crossCustomerBlocklist.entries()) {
    if (now > entry.expiresAt) {
      crossCustomerBlocklist.delete(ip);
    }
  }
}
