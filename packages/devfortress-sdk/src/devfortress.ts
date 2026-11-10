/**
 * DevFortress SDK v4.0.0 — Main DevFortress Class
 *
 * Unified closed-loop security: detect → enrich → alert → remediate
 *
 * Supports three protection modes:
 *   - EXTERNAL: SDK → Platform API → Webhook → Response (default)
 *   - INTERNAL: 3-tier local engine, no platform calls (enterprise/air-gap)
 *   - HYBRID:   Internal first (sub-ms), external relay for enrichment
 *
 * Tier gating (Package A, 2026-08-28):
 *   - Starter:    Observe; response is webhook-dispatched, self-executed
 *   - Pro:        Observe + block via external CL only — no internal/hybrid,
 *                 not even as an add-on
 *   - Team:       External, internal, and hybrid all first-class; default hybrid
 *   - Enterprise: All modes available; default hybrid
 *
 * Methods:
 *   - observe(req)           — observe every inbound request
 *   - enrichEvent(id, data)  — attach extra data to an in-flight event
 *   - isBlocked(ip, opts)    — check if IP/user/session is blocked
 *   - onThreatDetected(sev, handler) — register response action callbacks
 *   - reportActionTaken(id, report)  — confirm action execution to platform
 *   - handleWebhook(payload, signature, timestamp) — process incoming webhooks
 *   - getMode()              — current CL mode
 *   - getAudit()             — unified audit trail access
 */

import crypto from 'crypto';
import path from 'path';
import axios, { AxiosInstance, AxiosError } from 'axios';
import { SDK_VERSION } from './version';
import { attachPlatformSigning } from './ingest-signing';
import type {
  DevFortressConfig,
  CLMode,
  ObserveResult,
  ObserveOptions,
  ThreatEvent,
  ThreatSeverity,
  ThreatHandler,
  ActionReport,
  WebhookPayload,
  ApiResponse,
} from './types';
import {
  InternalClosedLoopEngine,
  BoundedMap,
  matchesKnownAttackPattern,
  type InternalCLConfig,
  type InternalCLRequest,
  type InternalCLResult,
} from './internal-closed-loop-engine';
import {
  MLClassifier,
  type EventFeatures,
  type ClassificationResult,
} from './ml-classifier';
import { PlatformCircuitBreaker } from './circuit-breaker';
import { UnifiedAuditTrail } from './unified-audit';
import { TierGate, type SubscriptionTier } from './tier-gate';
import { LicenseManager, type LicenseState } from './license-manager';
import { TelemetryManager } from './telemetry';
import { TelemetryRollupBuffer } from './telemetry-rollup-buffer';
import { WebhookNonceRegistry } from './webhook-nonce-registry';
import { GraduatedRateLimiter } from './graduated-rate-limiter';
import {
  ColdStartDetector,
  type BehavioralFeatureVector,
} from './cold-start-detector';
import {
  LSHClusterEngine,
  type RequestFingerprint,
} from './lsh-cluster-engine';

const DEFAULT_ENDPOINT = 'https://www.devfortress.net/api/events/ingest';
const DEFAULT_TIMEOUT = 20000;
const DEFAULT_RETRIES = 3;
const WEBHOOK_MAX_AGE_MS = 5 * 60 * 1000; // 5 minutes
// A1: minimum assess() confidence before a cold-start deviation
// actually flags a request — avoids false positives while the population
// baseline is still thin (see cold-start-detector.ts confidence formula).
const COLD_START_CONFIDENCE_THRESHOLD = 0.5;

/**
 * Derive the base API URL from the ingest endpoint.
 */
function deriveBaseUrl(endpoint: string): string {
  const url = new URL(endpoint);
  const parts = url.pathname.split('/').filter(Boolean);
  if (parts.length > 0 && parts[parts.length - 1] === 'ingest') {
    parts.pop();
  }
  url.pathname = '/' + parts.join('/');
  return url.toString().replace(/\/$/, '');
}

/**
 * Derive the platform root (the URL that /api/sdk/* routes hang off) from the
 * ingest endpoint by stripping a trailing /api/events/ingest.
 */
function derivePlatformBaseUrl(endpoint: string): string {
  const url = new URL(endpoint);
  const parts = url.pathname.split('/').filter(Boolean);
  for (const suffix of ['ingest', 'events', 'api']) {
    if (parts[parts.length - 1] === suffix) parts.pop();
    else break;
  }
  url.pathname = '/' + parts.join('/');
  return url.toString().replace(/\/$/, '');
}

// In-memory cache for blocking decisions — LRU bounded to prevent memory leaks
const MAX_CACHE_ENTRIES = 10_000;
const memoryCache = new BoundedMap<
  string,
  { value: string; expiresAt: number }
>(MAX_CACHE_ENTRIES);

function memGet(key: string): string | null {
  const entry = memoryCache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    memoryCache.delete(key);
    return null;
  }
  return entry.value;
}

function memSet(key: string, value: string, ttlSeconds: number): void {
  memoryCache.set(key, {
    value,
    expiresAt: Date.now() + ttlSeconds * 1000,
  });
}

/**
 * Detect whether an IP address is a private/reserved address.
 * Covers IPv4 private ranges and IPv6 link-local, unique-local, loopback,
 * and IPv4-mapped addresses.
 */
function isPrivateIP(ip: string): boolean {
  // IPv4 private ranges
  if (/^10\./.test(ip)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return true;
  if (/^192\.168\./.test(ip)) return true;
  if (/^127\./.test(ip)) return true;
  if (/^0\.0\.0\.0/.test(ip)) return true;
  if (/^169\.254\./.test(ip)) return true; // link-local IPv4

  // IPv6 private/reserved ranges
  const lowerIp = ip.toLowerCase();
  if (lowerIp === '::1') return true; // loopback
  if (/^fe80:/i.test(ip)) return true; // link-local
  if (/^f[cd][0-9a-f]{2}:/i.test(ip)) return true; // unique-local (fc00::/7 → fc/fd)
  if (/^::ffff:(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)/.test(lowerIp))
    return true; // IPv4-mapped

  return false;
}

export class DevFortressCore {
  protected apiKey: string;
  protected appId: string;
  private environment: string;
  protected debug: boolean;
  private endpoint: string;
  private timeout: number;
  private retries: number;
  private failClosed: boolean;
  private enrichment: DevFortressConfig['enrichment'];
  private responseWebhook: DevFortressConfig['responseWebhook'];
  private cacheConfig: DevFortressConfig['cache'];
  protected axios: AxiosInstance;
  private apiAxios: AxiosInstance;
  private webhookAxios: AxiosInstance;
  private handlers: Map<string, ThreatHandler[]> = new Map();

  // ── CL Mode Support ──────────────────────────────────────
  protected mode: CLMode;
  private internalEngine: InternalClosedLoopEngine | null = null;
  private circuitBreaker: PlatformCircuitBreaker | null = null;
  private auditTrail: UnifiedAuditTrail;
  protected tierGate: TierGate;
  // Option B (2026-08-27): buffers non-billed aggregate telemetry for clean
  // traffic. Only instantiated for modes that ever call observeExternal().
  private rollupBuffer: TelemetryRollupBuffer | null = null;

  // ── Revenue Protection (CV-M / CV-S) ─────────────────────
  private licenseManager: LicenseManager | null = null;
  private telemetryManager: TelemetryManager | null = null;
  private readonly _initTimestamp = Date.now();

  // S28: Webhook endpoint flooding protection
  private webhookDeliveryCounts = new Map<
    string,
    { count: number; windowStart: number }
  >();
  private static readonly WEBHOOK_RATE_LIMIT = 60; // max 60 deliveries per minute per endpoint
  private static readonly WEBHOOK_RATE_WINDOW_MS = 60_000; // 1 minute

  // S26: Token alias count limits per subject (prevent enumeration)
  private aliasCountsPerSubject = new BoundedMap<
    string,
    { count: number; windowStart: number }
  >(10_000);
  private static readonly MAX_ALIASES_PER_SUBJECT = 100; // max 100 aliases per subject per hour
  private static readonly ALIAS_COUNT_WINDOW_MS = 3_600_000; // 1 hour

  // ── A4: Webhook Nonce Registry (replay prevention) ────────
  private nonceRegistry: WebhookNonceRegistry;

  // ── A3: Graduated Rate Limiter ────────────────────────────
  private graduatedRateLimiter: GraduatedRateLimiter;

  // ── A1: Cold-Start Behavioral Baseline Detector ───────────
  private coldStartDetector: ColdStartDetector;
  private behaviorTracker = new BoundedMap<
    string,
    {
      requestCount: number;
      endpointCounts: Map<string, number>;
      firstSeen: number;
    }
  >(50_000);

  // ── A2: LSH Cross-Alias Correlation / Campaign Detection ──
  private lshClusterEngine: LSHClusterEngine;

  // ── TODO 192: Embedded ML classifier (Tier 2 scoring, Team/Enterprise only) ──
  private mlClassifier: MLClassifier | null = null;
  private lastTier2Classification: ClassificationResult | null = null;

  constructor(config: DevFortressConfig) {
    if (!config.apiKey) {
      throw new Error('DevFortress: apiKey is required');
    }
    if (!config.appId) {
      throw new Error('DevFortress: appId is required');
    }

    this.apiKey = config.apiKey;
    this.appId = config.appId;
    this.environment = config.environment || 'production';
    this.debug = config.debug || false;
    this.endpoint = config.endpoint || DEFAULT_ENDPOINT;
    this.timeout = config.timeout || DEFAULT_TIMEOUT;
    this.retries = config.retries || DEFAULT_RETRIES;
    this.failClosed = config.failClosed ?? false;
    this.enrichment = config.enrichment;
    this.responseWebhook = config.responseWebhook;
    this.cacheConfig = config.cache;

    // ── Tier gating ──
    const tier = (config.tier || 'starter') as SubscriptionTier;
    this.tierGate = new TierGate(tier, {
      hybridAddonEnabled: config.hybridAddonEnabled,
    });

    // ── Mode resolution (respects tier limits) ──
    this.mode = this.tierGate.getEffectiveMode(config.mode);

    // ── Initialize unified audit trail ──
    this.auditTrail = new UnifiedAuditTrail({ debug: this.debug });

    // ── A4: Initialize webhook nonce registry (replay prevention) ──
    this.nonceRegistry = new WebhookNonceRegistry({
      maxEntries: 100_000,
      ttlMs: 10 * 60 * 1000, // 10 minutes (2× timestamp window)
      clockSkewToleranceMs: 30_000, // 30 seconds
      enableMetrics: true,
    });

    // ── A3: Initialize graduated rate limiter ──
    this.graduatedRateLimiter = new GraduatedRateLimiter({
      defaultLimit: config.internalCL?.rateLimitMax ?? 100,
      windowMs: config.internalCL?.rateLimitWindowMs ?? 60_000,
      softLimitBaseLatencyMs: 2000,
      burstLimit: 20,
      initialCooldownSeconds: 60,
      maxConsecutiveBlocks: 3,
    });

    // ── A1: Initialize cold-start behavioral baseline detector ──
    this.coldStartDetector = new ColdStartDetector();

    // ── A2: Initialize LSH cross-alias correlation engine ──
    this.lshClusterEngine = new LSHClusterEngine();

    // ── Initialize internal engine for internal/hybrid modes ──
    if (this.mode === 'internal' || this.mode === 'hybrid') {
      // TODO 192: default Tier 2 scorer to the embedded MLClassifier for
      // tiers with ICL Tier 2 access (Team/Enterprise). Pro never reaches
      // this branch — it has no 'internal'/'hybrid' entry in allowedModes.
      // A caller-supplied tier2Scorer always takes precedence.
      let tier2Scorer = config.internalCL
        ?.tier2Scorer as InternalCLConfig['tier2Scorer'];
      if (!tier2Scorer && this.tierGate.getMaxICLTier() >= 2) {
        this.mlClassifier = new MLClassifier({
          modelPath: path.join(
            __dirname,
            '..',
            'models',
            'threat-classifier.onnx'
          ),
          // No platformEndpoint/apiKey — never falls through to the dormant
          // HF platform inference path. Heuristic remains the fallback if
          // ONNX Runtime or the model file is unavailable.
        });
        tier2Scorer = (req: InternalCLRequest) =>
          this.scoreWithMLClassifier(req);
      }

      const iclConfig: InternalCLConfig = {
        failMode: config.internalCL?.failMode ?? 'closed',
        enableExternalRelay: this.mode === 'hybrid',
        tier2Scorer,
        blockThreshold: config.internalCL?.blockThreshold ?? 85,
        rateLimitMax: config.internalCL?.rateLimitMax ?? 100,
        rateLimitWindowMs: config.internalCL?.rateLimitWindowMs ?? 60_000,
        debug: this.debug,
        // Option B (2026-08-27): Tier 3 relay — only ever invoked (by the
        // engine itself) for non-'allow' decisions when enableExternalRelay
        // is true, i.e. hybrid mode only. Reuses trackEvent()'s existing
        // payload-construction + sendWithRetry() path verbatim.
        onRelay: (result, req) =>
          this.relayInternalDecisionToPlatform(result, req),
      };
      this.internalEngine = new InternalClosedLoopEngine(iclConfig);
    }

    // ── Initialize circuit breaker for hybrid mode ──
    if (this.mode === 'hybrid') {
      this.circuitBreaker = new PlatformCircuitBreaker({
        failureThreshold: config.circuitBreaker?.failureThreshold ?? 3,
        recoveryTimeMs: config.circuitBreaker?.recoveryTimeMs ?? 60_000,
        onStateChange: (from, to, reason) => {
          this.log('warn', `Circuit breaker: ${from} → ${to} (${reason})`);
        },
      });
    }

    if (
      this.endpoint.startsWith('http://') &&
      !this.endpoint.includes('localhost') &&
      !this.endpoint.includes('127.0.0.1')
    ) {
      this.log(
        'warn',
        'Using non-HTTPS endpoint. API key will be transmitted in cleartext.'
      );
    }

    this.axios = axios.create({
      baseURL: this.endpoint,
      timeout: this.timeout,
      headers: {
        'Content-Type': 'application/json',
        'X-DevFortress-App': this.appId,
      },
    });
    attachPlatformSigning(this.axios, this.apiKey);

    const baseApiUrl = deriveBaseUrl(this.endpoint);
    const platformBaseUrl = derivePlatformBaseUrl(this.endpoint);
    this.apiAxios = axios.create({
      baseURL: baseApiUrl,
      timeout: this.timeout,
      headers: {
        'Content-Type': 'application/json',
        'X-DevFortress-App': this.appId,
      },
    });
    // Platform calls identify the project by key ID and are signed; the API
    // key is never sent.
    attachPlatformSigning(this.apiAxios, this.apiKey);
    // Deliveries to the customer's own webhook URL. Kept separate so nothing
    // that identifies the project (or its key) is ever sent to that host.
    this.webhookAxios = axios.create({
      timeout: this.timeout,
      headers: {
        'Content-Type': 'application/json',
        'X-DevFortress-App': this.appId,
      },
    });

    // ── Option B (2026-08-27): Aggregate Telemetry Rollup Buffer ──
    // Only meaningful for modes that ever call observeExternal() — external
    // (always) and hybrid (enrichment step). Buffers non-billed rollup
    // contributions for clean traffic and flushes them in small batches
    // instead of a full LiveThreatEvent row per clean request.
    if (this.mode === 'external' || this.mode === 'hybrid') {
      this.rollupBuffer = new TelemetryRollupBuffer({
        apiAxios: this.apiAxios,
        debug: this.debug,
      });
      this.rollupBuffer.start();
    }

    // ── License Manager (CV-M1, CV-M4, CV-M7) ──
    if (config.license?.enabled !== false) {
      this.licenseManager = new LicenseManager({
        apiKey: this.apiKey,
        endpoint: platformBaseUrl,
        checkIntervalMs: config.license?.checkIntervalMs,
        gracePeriodMs: config.license?.gracePeriodMs,
        debug: this.debug,
      });
      // Fire-and-forget — init runs background periodic check
      this.licenseManager.init().catch((err: Error) => {
        this.log('warn', `LicenseManager init failed: ${err.message}`);
      });
    }

    // ── Telemetry Heartbeat (CV-M2) ──
    if (config.telemetry?.enabled !== false) {
      this.telemetryManager = new TelemetryManager({
        apiKey: this.apiKey,
        endpoint: platformBaseUrl,
        heartbeatIntervalMs: config.telemetry?.heartbeatIntervalMs,
        debug: this.debug,
      });
      this.telemetryManager.start(() => ({
        eventCount: this.tierGate.getMonthlyUsage().used,
        blockCount: 0, // populated by recordBlock()
        rateLimitCount: 0,
        clMode: this.mode,
        tier,
        sdkVersion: SDK_VERSION,
        modelExpired: this.licenseManager?.isModelExpired() ?? false,
        licenseDegraded: this.licenseManager?.isDegraded() ?? false,
        integrityHash: this.licenseManager?.computeIntegrityHash() ?? '',
        uptimeSeconds: Math.floor((Date.now() - this._initTimestamp) / 1000),
        p99LatencyMs: 0,
      }));
    }

    this.log(
      'info',
      `DevFortress SDK v${SDK_VERSION} initialized (app=${this.appId}, mode=${this.mode}, tier=${tier})`
    );
  }

  // ── Mode & Tier Accessors ─────────────────────────────────

  /** Get the current closed-loop mode. */
  getMode(): CLMode {
    return this.mode;
  }

  /** Get the unified audit trail for querying/export. */
  getAudit(): UnifiedAuditTrail {
    return this.auditTrail;
  }

  /** Get the tier gate for capability checks. */
  getTierGate(): TierGate {
    return this.tierGate;
  }

  /** Get the internal engine (null if mode is external). */
  getInternalEngine(): InternalClosedLoopEngine | null {
    return this.internalEngine;
  }

  /**
   * Force an immediate flush of any buffered aggregate telemetry rollup
   * contributions (Option B, 2026-08-27) instead of waiting for the next
   * scheduled interval. No-op if rollup buffering isn't active for this
   * mode. Useful before process/serverless-function shutdown, and in tests.
   */
  async flushTelemetryRollup(): Promise<void> {
    await this.rollupBuffer?.flush();
  }

  /** Get circuit breaker diagnostics (null if not hybrid). */
  getCircuitBreakerDiagnostics(): ReturnType<
    PlatformCircuitBreaker['getDiagnostics']
  > | null {
    return this.circuitBreaker?.getDiagnostics() ?? null;
  }

  /** Get the license manager for status/diagnostics. */
  getLicenseManager(): LicenseManager | null {
    return this.licenseManager;
  }

  /** Get the telemetry manager for status/diagnostics. */
  getTelemetryManager(): TelemetryManager | null {
    return this.telemetryManager;
  }

  /** Get nonce registry metrics for monitoring (A4, GAP-A4-4). */
  getNonceRegistryStats(): import('./webhook-nonce-registry').NonceRegistryMetrics {
    return this.nonceRegistry.getMetrics();
  }

  /** Get the graduated rate limiter instance (A3). */
  getGraduatedRateLimiter(): GraduatedRateLimiter {
    return this.graduatedRateLimiter;
  }

  /** Destroy the SDK instance — cleans up timers and background tasks. */
  destroy(): void {
    this.licenseManager?.destroy();
    this.telemetryManager?.destroy();
    this.nonceRegistry.destroy();
    this.graduatedRateLimiter.destroy();
    this.rollupBuffer?.destroy();
    this.licenseManager = null;
    this.telemetryManager = null;
    this.rollupBuffer = null;
    this.log('info', 'DevFortress SDK destroyed');
  }

  // ── Observe ───────────────────────────────────────────────

  /**
   * Observe an inbound API request.
   * Behavior depends on mode:
   *   - EXTERNAL: Send to platform API
   *   - INTERNAL: Evaluate locally via 3-tier engine
   *   - HYBRID:   Evaluate locally first, then relay to platform
   */
  async observe(
    req: unknown,
    options?: ObserveOptions
  ): Promise<ObserveResult | null> {
    // ── CV-M1: License degradation — monitor only, no blocking ──
    if (this.licenseManager?.isDegraded()) {
      this.log(
        'warn',
        'License degraded — observe() in monitor-only mode (no blocking)'
      );
      this.telemetryManager?.recordEvent();
      return null;
    }

    // ── CV-S3: Monthly quota enforcement ──
    const monthlyQuota = this.tierGate.checkMonthlyQuota();
    if (!monthlyQuota.allowed) {
      this.log(
        'warn',
        `Monthly event quota exhausted (${monthlyQuota.limit - monthlyQuota.remaining}/${monthlyQuota.limit})`
      );
      return null;
    }
    this.tierGate.recordMonthlyEvent();

    // Check daily event limit (existing)
    const limitCheck = this.tierGate.checkEventLimit();
    if (!limitCheck.allowed) {
      this.log('warn', 'Daily event limit reached, skipping observe()');
      return null;
    }
    this.tierGate.recordEvent();

    try {
      const r = req as Record<string, unknown>;
      const method = (r.method as string) || 'GET';
      const path = (r.url as string) || (r.path as string) || '/';
      const headers =
        (r.headers as Record<string, string | string[] | undefined>) || {};

      let ip = '0.0.0.0';
      if (!options?.skipEnrichment && this.enrichment?.getIP) {
        ip = this.enrichment.getIP(req) || ip;
      } else {
        const forwarded = headers['x-forwarded-for'];
        ip =
          (typeof forwarded === 'string'
            ? forwarded.split(',')[0]?.trim()
            : undefined) ||
          (headers['x-real-ip'] as string) ||
          (r.ip as string) ||
          ((r.socket as { remoteAddress?: string } | undefined)
            ?.remoteAddress as string) ||
          ip;
      }

      let userId: string | null = null;
      let sessionId: string | null = null;
      if (!options?.skipEnrichment && this.enrichment) {
        if (this.enrichment.getUserId) {
          userId = await Promise.resolve(this.enrichment.getUserId(req));
        }
        if (this.enrichment.getSessionId) {
          sessionId = await Promise.resolve(this.enrichment.getSessionId(req));
        }
      }

      const userAgent =
        typeof headers['user-agent'] === 'string'
          ? headers['user-agent']
          : null;

      // ── A1/A2/A3: Behavioral pre-flight ──
      // Runs for every mode (external/internal/hybrid) since it's the one
      // request-observation path all three share. Cold-start baseline
      // deviation (A1), LSH campaign clustering (A2), and graduated rate
      // limiting (A3) all evaluate here; any of the three can flag the
      // request regardless of which CL mode ultimately handles it.
      const entityKey = sessionId || userId || ip;
      const preflight = this.runBehavioralPreflight(entityKey, {
        ip,
        method,
        path,
        userAgent: userAgent || undefined,
        headers,
      });
      if (preflight.injectedLatencyMs > 0) {
        await new Promise(resolve =>
          setTimeout(resolve, preflight.injectedLatencyMs)
        );
      }

      // ── Route to the correct CL mode ──
      // CV-S1: AbuseIPDB enrichment is only available in external/hybrid
      //        Internal mode gets zero cross-customer intelligence (CV-M3)
      let result: ObserveResult | null;
      if (this.mode === 'internal') {
        result = await this.observeInternal(
          {
            ip,
            method,
            path,
            userAgent: userAgent || undefined,
            userId,
            sessionId,
          },
          options
        );
      } else if (this.mode === 'hybrid') {
        result = await this.observeHybrid(
          {
            ip,
            method,
            path,
            userAgent: userAgent || undefined,
            userId,
            sessionId,
          },
          options,
          preflight
        );
      } else {
        result = await this.observeExternal(
          { ip, method, path, userAgent, userId, sessionId },
          options,
          preflight
        );
      }

      if (result && preflight.flagged) {
        result = {
          ...result,
          flagged: true,
          confidence: Math.max(result.confidence, preflight.confidence),
        };
      }

      this.telemetryManager?.recordEvent();
      if (result?.flagged) this.telemetryManager?.recordBlock();
      return result;
    } catch (error) {
      this.log(
        'error',
        `observe() failed: ${error instanceof Error ? error.message : 'Unknown'}`
      );
      return null;
    }
  }

  // ── Behavioral Pre-flight (A1 cold-start, A2 LSH campaign, A3 rate limit) ──

  /**
   * Runs the three standalone behavioral-detection engines (A1/A2/A3)
   * against a single inbound request and folds their findings into one
   * flag/confidence signal, ahead of mode-specific dispatch.
   */
  private runBehavioralPreflight(
    entityKey: string,
    ctx: {
      ip: string;
      method: string;
      path: string;
      userAgent?: string;
      headers: Record<string, string | string[] | undefined>;
    }
  ): {
    flagged: boolean;
    confidence: number;
    injectedLatencyMs: number;
    reasons: string[];
  } {
    const reasons: string[] = [];
    let flagged = false;
    let confidence = 0;
    let injectedLatencyMs = 0;

    // ── A3: Graduated rate limiting ──
    const rateResult = this.graduatedRateLimiter.check(entityKey, ctx.path);
    if (rateResult.blocked || rateResult.revoke) {
      flagged = true;
      confidence = Math.max(confidence, rateResult.revoke ? 1 : 0.9);
      reasons.push(`rate_limit:${rateResult.stage}`);
    }
    if (rateResult.injectedLatencyMs > 0) {
      injectedLatencyMs = rateResult.injectedLatencyMs;
    }

    // ── A1: Cold-start behavioral baseline ──
    // observe() is a per-request, pre-response entry point, so dimensions
    // that require response data (latency, status, body size) aren't
    // available here and are fed as a neutral 0 — they contribute no
    // anomaly signal since they're uniformly 0 across the whole population.
    // ColdStartDetector's own EWMA (recordObservation) accumulates the
    // available dimensions across calls; its formula/logic is untouched.
    const tracker = this.behaviorTracker.get(entityKey) ?? {
      requestCount: 0,
      endpointCounts: new Map<string, number>(),
      firstSeen: Date.now(),
    };
    tracker.requestCount++;
    if (
      tracker.endpointCounts.size < 100 ||
      tracker.endpointCounts.has(ctx.path)
    ) {
      tracker.endpointCounts.set(
        ctx.path,
        (tracker.endpointCounts.get(ctx.path) ?? 0) + 1
      );
    }
    this.behaviorTracker.set(entityKey, tracker);

    let endpointEntropy = 0;
    for (const count of tracker.endpointCounts.values()) {
      const p = count / tracker.requestCount;
      endpointEntropy -= p * Math.log2(p);
    }

    const features: BehavioralFeatureVector = {
      avgCallsPerSession: tracker.requestCount,
      endpointEntropy,
      avgRequestBytes: 0,
      avgLatencyMs: 0,
      avgSessionDurationMs: Date.now() - tracker.firstSeen,
      uniqueEndpoints: tracker.endpointCounts.size,
      errorRate: 0,
      timeOfDayBias: new Date().getHours(),
      avgResponseBodyBytes: 0,
    };
    this.coldStartDetector.recordObservation(entityKey, features);
    const coldStartResult = this.coldStartDetector.assess(entityKey, features);
    if (
      coldStartResult.suspicious &&
      coldStartResult.confidence >= COLD_START_CONFIDENCE_THRESHOLD
    ) {
      flagged = true;
      confidence = Math.max(confidence, coldStartResult.confidence);
      reasons.push(`cold_start:${coldStartResult.anomalousFeatures.join(',')}`);
    }

    // ── A2: LSH cross-alias correlation / campaign detection ──
    const headerSignature = Object.keys(ctx.headers)
      .filter(h =>
        ['accept', 'accept-language', 'accept-encoding'].includes(
          h.toLowerCase()
        )
      )
      .sort();
    const fingerprint: RequestFingerprint = {
      sourceId: entityKey,
      endpoint: ctx.path,
      method: ctx.method,
      headerSignature,
      userAgent: ctx.userAgent,
      timestamp: Date.now(),
    };
    const lshResult = this.lshClusterEngine.ingest(fingerprint);
    if (lshResult.campaign) {
      flagged = true;
      confidence = Math.max(confidence, lshResult.campaign.confidence);
      reasons.push(`lsh_campaign:${lshResult.clusterId}`);
    }

    return { flagged, confidence, injectedLatencyMs, reasons };
  }

  // ── External Observe ──────────────────────────────────────

  private async observeExternal(
    parsed: {
      ip: string;
      method: string;
      path: string;
      userAgent: string | null;
      userId: string | null;
      sessionId: string | null;
    },
    options?: ObserveOptions,
    preflight?: { flagged: boolean; confidence: number }
  ): Promise<ObserveResult | null> {
    // ── Option B (2026-08-27): Anomaly-Gated Metering ──
    // `preflight` is the already-computed A1/A2/A3 behavioral result from
    // observe() (see runBehavioralPreflight) — it costs nothing extra here,
    // it's just not being discarded anymore. Clean (unflagged) traffic is
    // routed to the lightweight, non-billed rollup buffer instead of a full
    // per-request relay + LiveThreatEvent row. This gate lives inside
    // observeExternal()'s existing send path and applies regardless of
    // which mode invoked it (external directly, or hybrid's enrichment
    // step) — it does not change mode selection/allowedModes/defaultMode.
    //
    // FEATURE_ANOMALY_GATED_METERING=false is an instant kill switch back to
    // pre-existing behavior (relay everything), following the same pattern
    // cached at construction) so it can be toggled without a redeploy.
    //
    // NOTE: tier-gate.ts's `iclMaxTier` capability (Starter:1, Pro:2,
    // Enterprise:3) is a separate, pre-existing, currently-unenforced
    // tier-gating mechanism (zero callers repo-wide as of the 2026-08-27
    // audit) — unrelated to this gate and intentionally not wired in here.
    // A future session reconciling ICL tiering should not end up building a
    // second, conflicting tier-gating mechanism alongside this one.
    //
    // `preflight` alone is NOT sufficient: it's purely behavioral (rate /
    // cold-start / campaign clustering) and needs accumulated history to
    // flag anything, so it can't catch a single, first-ever malicious
    // request. matchesKnownAttackPattern() adds a zero-latency content
    // check (same Tier 1 regex patterns the internal engine uses) so a
    // one-off SQLi/XSS/path-traversal/scanner request still relays even
    // though local behavioral preflight alone would call it clean — see
    // internal-closed-loop-engine.ts's doc comment on that function.
    const meteringGateEnabled =
      process.env.FEATURE_ANOMALY_GATED_METERING !== 'false';
    const contentFlagged = matchesKnownAttackPattern({
      path: parsed.path,
      userAgent: parsed.userAgent ?? undefined,
    });
    if (
      meteringGateEnabled &&
      preflight &&
      !preflight.flagged &&
      !contentFlagged
    ) {
      // No response data is available at observe()-time (pre-response entry
      // point — same limitation documented on the A1 cold-start preflight
      // above), so isError/latencyMs are reported as unknown/zero here.
      this.rollupBuffer?.add({
        aliasOrIpKey: parsed.ip,
        endpoint: parsed.path,
        isError: false,
        latencyMs: 0,
      });
      // The SDK's own local audit trail (getAudit()) is a separate feature
      // from platform billing/relay — customers rely on it for local
      // diagnostics regardless of whether this request was relayed. Skipping
      // the platform round-trip must not also skip this local record; a
      // rollup-routed entry is tagged distinctly (matchedRules) so it reads
      // differently from a genuine platform-confirmed 'allow'.
      this.auditTrail.record({
        eventId: `rollup_${Date.now().toString(36)}`,
        timestamp: Date.now(),
        source: 'external',
        tier: 0,
        decision: 'allow',
        score: 0,
        severity: 'low',
        latencyMs: 0,
        ip: parsed.ip,
        path: parsed.path,
        method: parsed.method,
        matchedRules: ['anomaly_gated_rollup'],
        userId: parsed.userId,
        sessionId: parsed.sessionId,
      });
      return null;
    }

    const startTime = performance.now();
    try {
      const payload = {
        eventType: 'custom',
        ip: parsed.ip,
        method: parsed.method,
        path: parsed.path,
        userAgent: parsed.userAgent,
        userId: parsed.userId,
        sessionId: parsed.sessionId,
        appId: this.appId,
        environment: this.environment,
        timestamp: new Date().toISOString(),
        // v4.3 mandatory observability fields
        severity: 'LOW',
        clMode: this.mode,
        authPhase: parsed.userId ? 'post_auth' : 'pre_auth',
        actionTaken: 'monitored',
        responseLatencyMs: 0, // will be updated after response
        securityArm: 'collect',
        metadata: {
          ...options?.meta,
        },
      };

      const response = await this.sendWithRetry(payload);
      const data = response.data as ApiResponse & {
        flagged?: boolean;
        event_id?: string;
        confidence?: number;
      };

      const latencyMs = performance.now() - startTime;

      this.auditTrail.record({
        eventId:
          data.eventId || data.event_id || `ext_${Date.now().toString(36)}`,
        timestamp: Date.now(),
        source: 'external',
        tier: 0,
        decision: data.flagged ? 'block' : 'allow',
        score: data.confidence ? data.confidence * 100 : 0,
        severity: data.flagged ? 'high' : 'low',
        latencyMs: Math.round(latencyMs),
        ip: parsed.ip,
        path: parsed.path,
        method: parsed.method,
        matchedRules: [],
        userId: parsed.userId,
        sessionId: parsed.sessionId,
      });

      if (data.flagged) {
        return {
          flagged: true,
          event_id: data.eventId || data.event_id || '',
          confidence: data.confidence || 0,
        };
      }

      return null;
    } catch (error) {
      this.log(
        'error',
        `observeExternal() failed: ${error instanceof Error ? error.message : 'Unknown'}`
      );
      return null;
    }
  }

  // ── Internal Observe (3-tier engine) ──────────────────────

  private async observeInternal(
    parsed: {
      ip: string;
      method: string;
      path: string;
      userAgent?: string;
      userId: string | null;
      sessionId: string | null;
    },
    options?: ObserveOptions
  ): Promise<ObserveResult | null> {
    if (!this.internalEngine) {
      this.log('error', 'Internal engine not initialized');
      return null;
    }

    const iclRequest: InternalCLRequest = {
      ip: parsed.ip,
      method: parsed.method,
      path: parsed.path,
      userAgent: parsed.userAgent,
      userId: parsed.userId,
      sessionId: parsed.sessionId,
      agentId: options?.meta?.agent_id as string | undefined,
      toolName: options?.meta?.tool_name as string | undefined,
    };

    const result = await this.internalEngine.evaluate(iclRequest);

    this.auditTrail.record({
      eventId: result.eventId,
      timestamp: Date.now(),
      source: 'internal',
      tier: result.tier,
      decision: result.decision,
      score: result.score,
      severity:
        result.score >= 85
          ? 'critical'
          : result.score >= 60
            ? 'high'
            : result.score >= 35
              ? 'medium'
              : 'low',
      latencyMs: result.evaluationTimeUs / 1000,
      ip: parsed.ip,
      path: parsed.path,
      method: parsed.method,
      matchedRules: result.matchedRules,
      userId: parsed.userId,
      agentId: options?.meta?.agent_id as string | undefined,
      sessionId: parsed.sessionId,
    });

    if (result.decision !== 'allow' && this.tierGate.canBlock()) {
      memSet(`blocked:ip:${parsed.ip}`, '1', 3600);
      await this.fireThreatHandlers(result, parsed, options);
    }

    if (result.decision !== 'allow') {
      return {
        flagged: true,
        event_id: result.eventId,
        confidence: result.score / 100,
      };
    }

    return null;
  }

  // ── Internal Engine Tier 3 Relay (Option B, 2026-08-27) ────
  //
  // Wired into InternalClosedLoopEngine's `onRelay` config callback (see
  // constructor). The engine calls this only for non-'allow' decisions when
  // enableExternalRelay is true (hybrid mode only) — already anomaly-gated
  // by the engine's own call sites, nothing further to gate here. Reuses
  // trackEvent()'s existing payload-construction + sendWithRetry() path;
  // does not build a new HTTP path.
  //
  // TODO 210 (2026-08-27): this is now the SOLE authoritative relay path
  // for hybrid-mode flagged decisions — observeHybrid() no longer also
  // calls relayToExternalAsync() for the same decision (see that method
  // and observeHybrid()'s flagged branch for the double-billing bug this
  // fixed).
  //
  // Field mapping notes (InternalCLResult/InternalCLRequest → trackEvent()):
  //   - eventType: trackEvent() needs a human-readable string with no direct
  //     source on InternalCLResult. Uses matchedRules[0] (the actual rule
  //     that fired, e.g. "sql_injection") when present, else falls back to
  //     `icl_${decision}` (e.g. "icl_rate_limit") — logged either way so the
  //     branch taken is visible in debug logs, not silently guessed.
  //   - severity: derived from score using the same thresholds already used
  //     for audit-trail severity in observeInternal() above.
  //   - actionTaken: mapped from `decision` onto trackEvent()'s existing
  //     actionTaken union; 'quarantine' has no exact match, so it maps to
  //     'flagged' (closest available value).
  // ── TODO 192: Tier 2 scoring via embedded MLClassifier ──
  // Adapts InternalCLRequest -> EventFeatures and ClassificationResult -> a
  // numeric 0-100 score, since InternalCLConfig['tier2Scorer'] only accepts
  // a number (see internal-closed-loop-engine.ts). The full ClassificationResult
  // (severity, confidence, modelSource, inferenceLatencyMs) is retained on
  // `lastTier2Classification` for diagnostics/validation via getLastTier2Classification().
  private static readonly SEVERITY_SCORE_BASE: Record<
    ClassificationResult['severity'],
    number
  > = { LOW: 40, MEDIUM: 65, HIGH: 85, CRITICAL: 100 };

  private async scoreWithMLClassifier(req: InternalCLRequest): Promise<number> {
    const features: EventFeatures = {
      eventType: 'normal_request',
      ip: req.ip,
      method: req.method,
      path: req.path,
      authPhase: req.userId ? 'post_auth' : 'pre_auth',
      isAgent: !!req.agentId,
      hourOfDay: new Date(req.timestamp ?? Date.now()).getHours(),
    };

    const result = await this.mlClassifier!.classify(features);
    this.lastTier2Classification = result;
    this.log(
      'debug',
      `ICL Tier 2 ML classification: severity=${result.severity} confidence=${result.confidence} modelSource=${result.modelSource} inferenceLatencyMs=${result.inferenceLatencyMs}`
    );

    const base = DevFortressCore.SEVERITY_SCORE_BASE[result.severity];
    return Math.round(Math.min(100, base * result.confidence));
  }

  /**
   * Diagnostic accessor for the most recent Tier 2 ML classification
   * (embedded MLClassifier). Returns null until the internal engine's Tier 2
   * scorer has run at least once. Exposed for validation/observability, not
   * used in the decision path itself.
   */
  getLastTier2Classification(): ClassificationResult | null {
    return this.lastTier2Classification;
  }

  private async relayInternalDecisionToPlatform(
    result: InternalCLResult,
    req: InternalCLRequest
  ): Promise<void> {
    const eventType = result.matchedRules[0]
      ? result.matchedRules[0]
      : `icl_${result.decision}`;
    this.log(
      'debug',
      `relayInternalDecisionToPlatform: eventType resolved to "${eventType}" ` +
        `(${result.matchedRules[0] ? 'from matchedRules[0]' : 'fallback to decision'})`
    );

    const severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' =
      result.score >= 85
        ? 'CRITICAL'
        : result.score >= 60
          ? 'HIGH'
          : result.score >= 35
            ? 'MEDIUM'
            : 'LOW';

    const actionTakenMap: Record<
      InternalCLResult['decision'],
      | 'blocked'
      | 'rate_limited'
      | 'session_revoked'
      | 'captcha_challenged'
      | 'challenge_required'
      | 'flagged'
      | 'allowed'
      | 'monitored'
    > = {
      allow: 'allowed',
      block: 'blocked',
      rate_limit: 'rate_limited',
      challenge: 'challenge_required',
      quarantine: 'flagged',
    };

    await this.trackEvent({
      eventType,
      ip: req.ip,
      severity,
      method: req.method,
      path: req.path,
      userAgent: req.userAgent,
      authPhase: req.userId ? 'post_auth' : 'pre_auth',
      actionTaken: actionTakenMap[result.decision],
      responseLatencyMs: Math.round(result.evaluationTimeUs / 1000),
      metadata: {
        source: 'internal-closed-loop-engine',
        tier: result.tier,
        matchedRules: result.matchedRules,
        internalEventId: result.eventId,
        sessionId: req.sessionId,
        agentId: req.agentId,
      },
    });
  }

  // ── Hybrid Observe (internal first, external relay) ───────

  private async observeHybrid(
    parsed: {
      ip: string;
      method: string;
      path: string;
      userAgent?: string;
      userId: string | null;
      sessionId: string | null;
    },
    options?: ObserveOptions,
    preflight?: { flagged: boolean; confidence: number }
  ): Promise<ObserveResult | null> {
    // Step 1: Internal evaluation (immediate, sub-ms)
    const internalResult = await this.observeInternal(parsed, options);

    // Step 2: If internal blocked, return immediately.
    if (internalResult?.flagged) {
      // TODO 210 (2026-08-27): this used to ALSO call
      // relayToExternalAsync() here (old "S27" comment below), on top of
      // the internal engine's own onRelay callback — wired in the
      // constructor, see internal-closed-loop-engine.ts's Tier 3 relay —
      // which independently fires for this exact decision whenever
      // enableExternalRelay is true (hybrid mode, always true in this
      // method). Both were unconditionally sending a LiveThreatEvent row
      // for the same flagged request: real double-billing, confirmed via
      // repeated repro, not just a theoretical race. onRelay
      // (relayInternalDecisionToPlatform) is now the sole authoritative
      // relay path for hybrid-mode flagged decisions — it's the
      // architecturally-intended Tier 3 mechanism and carries
      // real matchedRules/severity/actionTaken from `result`, unlike the
      // old call here, which built a generic 'custom'/LOW-severity payload
      // with no reference to `internalResult` at all.
      //
      // Trade-off (see TODO 210 session report): relayToExternalAsync()'s
      // observeExternal() call also fetched an independent EXTERNAL verdict
      // and recorded it into the local SDK audit trail for "conflict
      // resolution" (old S27 comment: "if external overrides, the dedup in
      // audit trail merges entries"). That verdict fetch and the duplicate
      // billed relay were the same network call, so removing the call here
      // also drops that conflict-resolution audit entry for hybrid-mode
      // blocked requests — trackEvent() (onRelay's path) has no equivalent.
      // Not fixed here; would need a platform-side verdict-only/no-bill
      // endpoint, out of scope for an SDK-only dedupe fix.
      return internalResult;
    }

    // Step 3: External enrichment (if circuit allows)
    if (this.circuitBreaker && this.circuitBreaker.shouldCallExternal()) {
      try {
        // Option B: `preflight` is passed through so clean traffic gets the
        // same rollup-instead-of-relay gating here as plain external mode —
        // this enrichment call is otherwise identical to external mode's.
        const externalResult = await this.observeExternal(
          { ...parsed, userAgent: parsed.userAgent || null },
          options,
          preflight
        );

        this.circuitBreaker.recordSuccess();

        if (externalResult?.flagged) {
          this.auditTrail.record({
            eventId: externalResult.event_id,
            timestamp: Date.now(),
            source: 'hybrid',
            tier: 0,
            decision: 'block',
            score: externalResult.confidence * 100,
            severity: 'high',
            latencyMs: 0,
            ip: parsed.ip,
            path: parsed.path,
            method: parsed.method,
            matchedRules: ['external_enrichment'],
            userId: parsed.userId,
            sessionId: parsed.sessionId,
            fallbackMode: false,
          });
          return externalResult;
        }

        return null;
      } catch {
        this.circuitBreaker.recordFailure();
        this.log('warn', 'External CL unavailable, relying on internal-only');

        this.auditTrail.record({
          eventId: `fb_${Date.now().toString(36)}`,
          timestamp: Date.now(),
          source: 'hybrid',
          tier: 0,
          decision: 'allow',
          score: 0,
          severity: 'low',
          latencyMs: 0,
          ip: parsed.ip,
          path: parsed.path,
          method: parsed.method,
          matchedRules: ['fallback_to_internal'],
          userId: parsed.userId,
          sessionId: parsed.sessionId,
          fallbackMode: true,
        });

        return null;
      }
    } else {
      this.log('debug', 'Circuit open, using internal-only mode');
      return null;
    }
  }

  // ── Async Relay for Hybrid Mode ───────────────────────────
  //
  // TODO 210 (2026-08-27): no longer called from observeHybrid()'s flagged
  // branch (see the comment there) — onRelay/relayInternalDecisionToPlatform
  // is now the sole authoritative Tier 3 relay path for hybrid-mode flagged
  // decisions, to stop double-billing a single decision via two independent
  // relays. Left intact (not deleted) because its observeExternal() call
  // also fetches an independent external verdict for local audit-trail
  // conflict resolution, which onRelay's path doesn't replicate — see the
  // TODO 210 session report for the trade-off this created and why it
  // wasn't preserved here.

  private async relayToExternalAsync(
    parsed: {
      ip: string;
      method: string;
      path: string;
      userAgent?: string;
      userId: string | null;
      sessionId: string | null;
    },
    options?: ObserveOptions
  ): Promise<void> {
    if (!this.circuitBreaker?.shouldCallExternal()) return;
    try {
      await this.observeExternal(
        { ...parsed, userAgent: parsed.userAgent || null },
        options
      );
      this.circuitBreaker?.recordSuccess();
    } catch {
      this.circuitBreaker?.recordFailure();
    }
  }

  // ── Fire Threat Handlers ──────────────────────────────────

  private async fireThreatHandlers(
    result: InternalCLResult,
    parsed: {
      ip: string;
      method: string;
      path: string;
      userId: string | null;
      sessionId: string | null;
    },
    options?: ObserveOptions
  ): Promise<void> {
    const severity: ThreatSeverity =
      result.score >= 85
        ? 'critical'
        : result.score >= 60
          ? 'high'
          : result.score >= 35
            ? 'medium'
            : 'low';

    const threatEvent: ThreatEvent = {
      event_id: result.eventId,
      threat_type: result.matchedRules.join(', ') || 'internal_detection',
      severity,
      confidence: result.score / 100,
      composite_score: result.score,
      ip: parsed.ip,
      identity: {
        user_id: parsed.userId,
        session_id: parsed.sessionId,
      },
      endpoint: parsed.path,
      method: parsed.method,
      timestamp: new Date().toISOString(),
      meta: {
        ...(options?.meta || {}),
        source: 'internal',
        tier: result.tier,
        evaluation_time_us: result.evaluationTimeUs,
      },
    };

    const specificHandlers = this.handlers.get(severity) || [];
    const wildcardHandlers = this.handlers.get('*') || [];

    for (const handler of [...specificHandlers, ...wildcardHandlers]) {
      try {
        await handler(threatEvent);
      } catch (error) {
        this.log(
          'error',
          `Threat handler error: ${error instanceof Error ? error.message : 'Unknown'}`
        );
      }
    }
  }

  // ── Enrichment ────────────────────────────────────────────

  async enrichEvent(
    eventId: string,
    additionalData: Record<string, unknown>
  ): Promise<void> {
    if (this.mode === 'internal') {
      this.log('debug', `enrichEvent() is a no-op in internal mode`);
      return;
    }
    try {
      await this.apiAxios.patch(`/enrich/${eventId}`, additionalData);
      this.log('debug', `Enriched event ${eventId}`);
    } catch (error) {
      this.log(
        'error',
        `enrichEvent() failed: ${error instanceof Error ? error.message : 'Unknown'}`
      );
    }
  }

  // ── Blocking Check ────────────────────────────────────────

  async isBlocked(
    ip: string,
    options?: { userId?: string; sessionId?: string }
  ): Promise<boolean> {
    // ── CV-M1: Degraded license cannot block ──
    if (this.licenseManager?.isDegraded()) {
      this.log('warn', 'License degraded — isBlocked() always returns false');
      return false;
    }

    // ── Skip private/reserved IPs (never block internal traffic) ──
    if (isPrivateIP(ip)) {
      this.log('debug', `Skipping private IP: ${ip}`);
      return false;
    }

    if (this.internalEngine) {
      if (this.internalEngine.isIPBlocked(ip)) return true;
    }

    if (memGet(`blocked:ip:${ip}`)) return true;
    if (options?.userId && memGet(`blocked:user:${options.userId}`))
      return true;
    if (options?.sessionId && memGet(`blocked:session:${options.sessionId}`))
      return true;

    if (this.mode === 'internal') return false;

    try {
      const response = await this.apiAxios.get('/blocked', {
        params: { ip, userId: options?.userId, sessionId: options?.sessionId },
      });
      const blocked = (response.data as { blocked: boolean }).blocked;
      if (blocked) {
        memSet(`blocked:ip:${ip}`, '1', this.cacheConfig?.ttl || 3600);
      }
      return blocked;
    } catch {
      const mode = this.failClosed ? 'closed' : 'open';
      this.log('warn', `isBlocked() check failed for ${ip}, failing ${mode}`);
      return this.failClosed;
    }
  }

  // ── Threat Handlers ───────────────────────────────────────

  onThreatDetected(
    severity: ThreatSeverity | '*',
    handler: ThreatHandler
  ): void {
    if (!this.handlers.has(severity)) {
      this.handlers.set(severity, []);
    }
    this.handlers.get(severity)!.push(handler);
    this.log('debug', `Registered threat handler for severity: ${severity}`);
  }

  // ── Action Reporting ──────────────────────────────────────

  async reportActionTaken(
    eventId: string,
    report: ActionReport
  ): Promise<void> {
    if (this.mode === 'internal') {
      this.log(
        'debug',
        `reportActionTaken() recorded locally in internal mode`
      );
      return;
    }
    try {
      await this.apiAxios.post('/actions/confirm', {
        event_id: eventId,
        ...report,
        timestamp: new Date().toISOString(),
      });
      this.log(
        'info',
        `Action confirmed for event ${eventId}: ${report.actions.join(', ')}`
      );
    } catch (error) {
      this.log(
        'error',
        `reportActionTaken() failed: ${error instanceof Error ? error.message : 'Unknown'}`
      );
    }
  }

  // ── Webhook Processing ────────────────────────────────────

  async handleWebhook(
    rawBody: string,
    signature: string,
    timestamp: string
  ): Promise<boolean> {
    if (!this.responseWebhook?.secret) {
      this.log(
        'error',
        'handleWebhook() called but no webhook secret configured'
      );
      return false;
    }

    const webhookTime = new Date(timestamp).getTime();
    if (isNaN(webhookTime) || Date.now() - webhookTime > WEBHOOK_MAX_AGE_MS) {
      this.log('warn', 'Webhook rejected: timestamp too old or invalid');
      return false;
    }

    const expectedSignature = crypto
      .createHmac('sha256', this.responseWebhook.secret)
      .update(`${timestamp}.${rawBody}`)
      .digest('hex');

    const sigBuffer = Buffer.from(signature, 'hex');
    const expectedBuffer = Buffer.from(expectedSignature, 'hex');

    if (
      sigBuffer.length !== expectedBuffer.length ||
      !crypto.timingSafeEqual(sigBuffer, expectedBuffer)
    ) {
      this.log('warn', 'Webhook rejected: invalid signature');
      return false;
    }

    let payload: WebhookPayload;
    try {
      payload = JSON.parse(rawBody);
    } catch {
      this.log('error', 'Webhook rejected: invalid JSON body');
      return false;
    }

    // ── A4: Nonce-based replay prevention (GAP-A4-1 through A4-4) ──
    // Mandatory by default — a missing nonce is rejected unless the caller
    // has explicitly opted into legacy senders via
    // responseWebhook.allowLegacyUnsignedWebhooks.
    const nonce = (payload as unknown as Record<string, unknown>).nonce as
      | string
      | undefined;
    if (nonce !== undefined) {
      const nonceResult = this.nonceRegistry.validateAndRegister(nonce);
      if (!nonceResult.valid) {
        this.log(
          'warn',
          `Webhook rejected: nonce ${nonceResult.reason} (nonce=${nonce?.substring(0, 8)}...)`
        );
        return false;
      }
    } else if (!this.responseWebhook.allowLegacyUnsignedWebhooks) {
      this.log(
        'warn',
        'Webhook rejected: missing nonce (replay protection is mandatory) — set responseWebhook.allowLegacyUnsignedWebhooks=true to permit legacy senders'
      );
      return false;
    }

    const threatEvent: ThreatEvent = {
      event_id: payload.event_id,
      threat_type: payload.threat_type,
      severity: payload.severity,
      confidence: payload.confidence,
      composite_score: payload.composite_score,
      ip: payload.ip,
      identity: payload.identity,
      geo: payload.geo,
      abuseipdb: payload.abuseipdb,
      endpoint: payload.endpoint,
      method: payload.method,
      timestamp: payload.timestamp,
      meta: payload.meta || {},
    };

    if (this.tierGate.canBlock()) {
      if (payload.severity === 'critical' || payload.severity === 'high') {
        memSet(`blocked:ip:${payload.ip}`, '1', this.cacheConfig?.ttl || 3600);
        if (payload.identity.user_id) {
          memSet(
            `blocked:user:${payload.identity.user_id}`,
            '1',
            this.cacheConfig?.ttl || 3600
          );
        }
        if (this.internalEngine) {
          this.internalEngine.blockIP(
            payload.ip,
            `webhook:${payload.threat_type}`,
            this.cacheConfig?.ttl || 3600
          );
        }
      }
    }

    this.auditTrail.record({
      eventId: payload.event_id,
      timestamp: Date.now(),
      source: 'external',
      tier: 0,
      decision: 'webhook_response',
      score: payload.composite_score,
      severity: payload.severity,
      latencyMs: 0,
      ip: payload.ip,
      path: payload.endpoint,
      method: payload.method,
      matchedRules: [payload.threat_type],
      userId: payload.identity.user_id,
      sessionId: payload.identity.session_id,
    });

    const specificHandlers = this.handlers.get(payload.severity) || [];
    const wildcardHandlers = this.handlers.get('*') || [];

    for (const handler of [...specificHandlers, ...wildcardHandlers]) {
      try {
        await handler(threatEvent);
      } catch (error) {
        this.log(
          'error',
          `Threat handler error: ${error instanceof Error ? error.message : 'Unknown'}`
        );
      }
    }

    this.log(
      'info',
      `Webhook processed: ${payload.event_id} [${payload.severity}] ${payload.threat_type}`
    );
    return true;
  }

  // ── IP Blocking ───────────────────────────────────────────

  blockIP(ip: string, ttlSeconds?: number): void {
    const error = this.tierGate.validateBlockAction('block_ip');
    if (error) {
      this.log('warn', error);
      return;
    }
    memSet(
      `blocked:ip:${ip}`,
      '1',
      ttlSeconds || this.cacheConfig?.ttl || 3600
    );
    if (this.internalEngine) {
      this.internalEngine.blockIP(ip, 'manual', ttlSeconds);
    }
    this.log('info', `IP blocked: ${ip}`);
  }

  unblockIP(ip: string): void {
    memoryCache.delete(`blocked:ip:${ip}`);
    if (this.internalEngine) {
      this.internalEngine.unblockIP(ip);
    }
    this.log('info', `IP unblocked: ${ip}`);
  }

  // ── Track Event ───────────────────────────────────────────

  async trackEvent(event: {
    eventType: string;
    ip: string;
    severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    method?: string;
    path?: string;
    userAgent?: string;
    statusCode?: number;
    authPhase?: 'pre_auth' | 'post_auth';
    actionTaken?:
      | 'blocked'
      | 'rate_limited'
      | 'session_revoked'
      | 'captcha_challenged'
      | 'challenge_required'
      | 'flagged'
      | 'allowed'
      | 'monitored';
    responseLatencyMs?: number;
    metadata?: Record<string, unknown>;
  }): Promise<{ success: boolean; eventId?: string }> {
    // ── CV-M1: License degradation — monitor only ──
    if (this.licenseManager?.isDegraded()) {
      this.telemetryManager?.recordEvent();
      return { success: false };
    }

    // ── CV-S3: Monthly quota ──
    const monthlyQuota = this.tierGate.checkMonthlyQuota();
    if (!monthlyQuota.allowed) {
      return { success: false };
    }
    this.tierGate.recordMonthlyEvent();

    const limitCheck = this.tierGate.checkEventLimit();
    if (!limitCheck.allowed) {
      return { success: false };
    }
    this.tierGate.recordEvent();

    if (this.mode === 'internal' && this.internalEngine) {
      const result = await this.internalEngine.evaluate({
        ip: event.ip,
        method: event.method || 'GET',
        path: event.path || '/',
        userAgent: event.userAgent,
      });

      if (result.decision !== 'allow' && this.tierGate.canBlock()) {
        if (event.severity === 'HIGH' || event.severity === 'CRITICAL') {
          const severity = event.severity.toLowerCase() as ThreatSeverity;
          const handlers = [
            ...(this.handlers.get(severity) || []),
            ...(this.handlers.get('*') || []),
          ];
          const threatEvent: ThreatEvent = {
            event_id: result.eventId,
            threat_type: event.eventType,
            severity,
            confidence: result.score / 100,
            composite_score: result.score,
            ip: event.ip,
            identity: { user_id: null, session_id: null },
            endpoint: event.path || '/',
            method: event.method || 'GET',
            timestamp: new Date().toISOString(),
            meta: event.metadata || {},
          };
          for (const handler of handlers) {
            try {
              await Promise.resolve(handler(threatEvent));
            } catch (e) {
              this.log(
                'error',
                `Threat handler error: ${e instanceof Error ? e.message : 'Unknown'}`
              );
            }
          }
        }
      }
      return { success: true, eventId: result.eventId };
    }

    try {
      const payload = {
        eventType: event.eventType,
        ip: event.ip,
        severity: event.severity || 'MEDIUM',
        method: event.method || 'GET',
        requestPath: event.path,
        userAgent: event.userAgent,
        statusCode: event.statusCode,
        // v4.3 mandatory observability fields
        clMode: this.mode,
        authPhase: event.authPhase || 'pre_auth',
        actionTaken: event.actionTaken || 'monitored',
        responseLatencyMs: event.responseLatencyMs ?? 0,
        securityArm:
          event.actionTaken === 'blocked' ||
          event.actionTaken === 'rate_limited' ||
          event.actionTaken === 'session_revoked'
            ? 'respond'
            : event.severity === 'HIGH' || event.severity === 'CRITICAL'
              ? 'detect'
              : 'collect',
        metadata: {
          ...event.metadata,
          appId: this.appId,
          environment: this.environment,
          sdk_version: SDK_VERSION,
        },
        timestamp: new Date().toISOString(),
      };

      const response = await this.sendWithRetry(payload);
      const data = response.data as ApiResponse & { eventId?: string };

      if (data.success) {
        this.log(
          'debug',
          `trackEvent(${event.eventType}) sent for ${event.ip}`
        );
        if (event.severity === 'HIGH' || event.severity === 'CRITICAL') {
          const severity = event.severity.toLowerCase() as ThreatSeverity;
          const handlers = [
            ...(this.handlers.get(severity) || []),
            ...(this.handlers.get('*') || []),
          ];
          const threatEvent: ThreatEvent = {
            event_id: data.eventId || '',
            threat_type: event.eventType,
            severity,
            confidence: 0.9,
            composite_score: event.severity === 'CRITICAL' ? 95 : 75,
            ip: event.ip,
            identity: { user_id: null, session_id: null },
            endpoint: event.path || '/',
            method: event.method || 'GET',
            timestamp: new Date().toISOString(),
            meta: event.metadata || {},
          };
          for (const handler of handlers) {
            try {
              await Promise.resolve(handler(threatEvent));
            } catch (e) {
              this.log(
                'error',
                `Threat handler error: ${e instanceof Error ? e.message : 'Unknown'}`
              );
            }
          }
        }
      }
      return { success: !!data.success, eventId: data.eventId };
    } catch (error) {
      this.log(
        'error',
        `trackEvent() failed: ${error instanceof Error ? error.message : 'Unknown'}`
      );
      return { success: false };
    }
  }

  // ── Test IPs ──────────────────────────────────────────────

  async registerTestIPs(ips: string[]): Promise<boolean> {
    if (this.mode === 'internal') {
      this.log('debug', 'registerTestIPs() is a no-op in internal mode');
      return true;
    }
    try {
      const response = await this.apiAxios.post('/test-ips', { ips });
      const data = response.data as { success: boolean; testIPs: string[] };
      this.log('info', `Registered ${ips.length} test IPs: ${ips.join(', ')}`);
      return data.success;
    } catch (error) {
      this.log(
        'error',
        `registerTestIPs() failed: ${error instanceof Error ? error.message : 'Unknown'}`
      );
      return false;
    }
  }

  // ── SDK Status (connection + closedLoop fields) ────────────

  /**
   * Returns SDK status including platform connection state and CL mode.
   * Used by /api/devfortress/status endpoints in client apps.
   */
  async getStatus(): Promise<{
    connected: boolean;
    closedLoop: CLMode;
    mode: CLMode;
    version: string;
    appId: string;
    tier: string;
    internalEngineActive: boolean;
  }> {
    let connected = false;
    if (this.mode === 'internal') {
      connected = this.internalEngine !== null;
    } else {
      try {
        const response = await this.apiAxios.get('/health', { timeout: 3000 });
        connected = response.status === 200;
      } catch {
        connected = false;
      }
    }

    return {
      connected,
      closedLoop: this.mode || 'external',
      mode: this.mode || 'external',
      version: SDK_VERSION,
      appId: this.appId,
      tier: this.tierGate?.getTier?.() ?? 'unknown',
      internalEngineActive: this.internalEngine !== null,
    };
  }

  // ── Test Connection ───────────────────────────────────────

  async testConnection(): Promise<boolean> {
    if (this.mode === 'internal') {
      return this.internalEngine !== null;
    }
    try {
      const response = await this.axios.post('', {
        eventType: 'custom',
        ip: '127.0.0.1',
        method: 'POST',
        path: '/devfortress/test',
        severity: 'LOW',
        clMode: this.mode || 'external',
        authPhase: 'pre_auth',
        actionTaken: 'monitored',
        responseLatencyMs: 0,
        appId: this.appId,
        metadata: { test: true, sdk_version: SDK_VERSION, mode: this.mode },
        timestamp: new Date().toISOString(),
      });
      return (response.data as ApiResponse).success === true;
    } catch {
      return false;
    }
  }

  // ── Webhook Callback Delivery (S19) ───────────────────────

  /**
   * Deliver a session revocation command to the customer webhook endpoint.
   * Awaits confirmation with a <2s SLA timeout.
   * Returns true if the customer SDK acknowledged within SLA.
   */
  async deliverSessionRevocation(params: {
    sessionId: string;
    userId?: string;
    reason: string;
    ip?: string;
  }): Promise<{ delivered: boolean; ackMs: number }> {
    if (!this.responseWebhook?.url || !this.responseWebhook?.secret) {
      this.log('warn', 'deliverSessionRevocation: no webhook configured');
      return { delivered: false, ackMs: 0 };
    }

    // S28: Webhook flooding protection
    if (!this.checkWebhookRateLimit(this.responseWebhook.url)) {
      this.log(
        'warn',
        `deliverSessionRevocation: rate limited (max ${DevFortressCore.WEBHOOK_RATE_LIMIT}/min)`
      );
      return { delivered: false, ackMs: 0 };
    }

    const timestamp = new Date().toISOString();
    const body = JSON.stringify({
      type: 'session_revocation',
      session_id: params.sessionId,
      user_id: params.userId || null,
      reason: params.reason,
      ip: params.ip || null,
      issued_at: timestamp,
    });

    const signature = crypto
      .createHmac('sha256', this.responseWebhook.secret)
      .update(`${timestamp}.${body}`)
      .digest('hex');

    const startMs = Date.now();
    try {
      await this.webhookAxios.post(this.responseWebhook.url, body, {
        headers: {
          'Content-Type': 'application/json',
          'X-DevFortress-Signature': signature,
          'X-DevFortress-Timestamp': timestamp,
        },
        timeout: 2000, // 2s SLA
      });
      const ackMs = Date.now() - startMs;
      this.log(
        'info',
        `Session revocation delivered in ${ackMs}ms (session=${params.sessionId})`
      );

      this.auditTrail.record({
        eventId: `wr_${Date.now().toString(36)}`,
        timestamp: Date.now(),
        source: 'external',
        tier: 0,
        decision: 'block',
        score: 0,
        severity: 'high',
        latencyMs: ackMs,
        ip: params.ip || '0.0.0.0',
        path: '/webhook/session-revocation',
        method: 'POST',
        matchedRules: ['session_revocation_webhook'],
        sessionId: params.sessionId,
        meta: {
          webhookAction: 'session_revocation_delivered',
          detail: `Revocation webhook for session ${params.sessionId} acked in ${ackMs}ms`,
        },
      });

      return { delivered: true, ackMs };
    } catch (error) {
      const ackMs = Date.now() - startMs;
      this.log(
        'error',
        `Session revocation webhook failed: ${error instanceof Error ? error.message : 'Unknown'} (${ackMs}ms)`
      );
      return { delivered: false, ackMs };
    }
  }

  /**
   * Deliver an IP block command to the customer webhook endpoint
   * so they can enforce at the edge (CDN/WAF/load balancer).
   */
  async deliverIPBlock(params: {
    ip: string;
    reason: string;
    ttlSeconds?: number;
    severity?: ThreatSeverity;
  }): Promise<{ delivered: boolean; ackMs: number }> {
    if (!this.responseWebhook?.url || !this.responseWebhook?.secret) {
      this.log('warn', 'deliverIPBlock: no webhook configured');
      return { delivered: false, ackMs: 0 };
    }

    // S28: Webhook flooding protection
    if (!this.checkWebhookRateLimit(this.responseWebhook.url)) {
      this.log(
        'warn',
        `deliverIPBlock: rate limited (max ${DevFortressCore.WEBHOOK_RATE_LIMIT}/min)`
      );
      return { delivered: false, ackMs: 0 };
    }

    const timestamp = new Date().toISOString();
    const body = JSON.stringify({
      type: 'ip_block',
      ip: params.ip,
      reason: params.reason,
      ttl_seconds: params.ttlSeconds || 3600,
      severity: params.severity || 'high',
      issued_at: timestamp,
    });

    const signature = crypto
      .createHmac('sha256', this.responseWebhook.secret)
      .update(`${timestamp}.${body}`)
      .digest('hex');

    const startMs = Date.now();
    try {
      await this.webhookAxios.post(this.responseWebhook.url, body, {
        headers: {
          'Content-Type': 'application/json',
          'X-DevFortress-Signature': signature,
          'X-DevFortress-Timestamp': timestamp,
        },
        timeout: 5000,
      });
      const ackMs = Date.now() - startMs;
      this.log(
        'info',
        `IP block webhook delivered in ${ackMs}ms (ip=${params.ip})`
      );

      this.auditTrail.record({
        eventId: `wb_${Date.now().toString(36)}`,
        timestamp: Date.now(),
        source: 'external',
        tier: 0,
        decision: 'block',
        score: 0,
        severity: params.severity || 'high',
        latencyMs: ackMs,
        ip: params.ip,
        path: '/webhook/ip-block',
        method: 'POST',
        matchedRules: ['ip_block_webhook'],
        meta: {
          webhookAction: 'ip_block_delivered',
          detail: `Block webhook for ${params.ip} acked in ${ackMs}ms`,
        },
      });

      return { delivered: true, ackMs };
    } catch (error) {
      const ackMs = Date.now() - startMs;
      this.log(
        'error',
        `IP block webhook failed: ${error instanceof Error ? error.message : 'Unknown'} (${ackMs}ms)`
      );
      return { delivered: false, ackMs };
    }
  }


  /**
   * Generate a tamper-proof alias for a token/session.
   * Uses HMAC-SHA256 so the alias can be verified without storing plaintext.
   * S26: Enforces per-subject rate limit (100 aliases/hour) to prevent enumeration.
   * @param token The token to alias
   * @param subject Optional subject identifier (userId, sessionId) for rate limiting. Defaults to 'default'.
   */
  generateTokenAlias(
    token: string,
    subject?: string
  ): { alias: string; signature: string } | null {
    // S26: Enforce per-subject alias count limit
    const subjectKey = subject || 'default';
    const now = Date.now();
    const bucket = this.aliasCountsPerSubject.get(subjectKey);

    if (
      bucket &&
      now - bucket.windowStart < DevFortressCore.ALIAS_COUNT_WINDOW_MS
    ) {
      if (bucket.count >= DevFortressCore.MAX_ALIASES_PER_SUBJECT) {
        this.log(
          'warn',
          `generateTokenAlias: subject "${subjectKey}" exceeded alias limit (${DevFortressCore.MAX_ALIASES_PER_SUBJECT}/hour)`
        );
        return null;
      }
      bucket.count++;
    } else {
      this.aliasCountsPerSubject.set(subjectKey, {
        count: 1,
        windowStart: now,
      });
    }

    const aliasKey = this.apiKey; // Use API key as HMAC secret
    const alias = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex')
      .slice(0, 16);
    const signature = crypto
      .createHmac('sha256', aliasKey)
      .update(alias)
      .digest('hex');
    return { alias, signature };
  }

  /**
   * Verify a token alias integrity (detect tampering/replay).
   * Returns true if the alias matches the expected HMAC signature.
   */
  verifyTokenAlias(alias: string, signature: string): boolean {
    const aliasKey = this.apiKey;
    const expected = crypto
      .createHmac('sha256', aliasKey)
      .update(alias)
      .digest('hex');

    const sigBuffer = Buffer.from(signature, 'hex');
    const expectedBuffer = Buffer.from(expected, 'hex');

    if (sigBuffer.length !== expectedBuffer.length) return false;
    return crypto.timingSafeEqual(sigBuffer, expectedBuffer);
  }

  /**
   * Sign an event payload with HMAC to detect tampering in transit.
   * Attach the returned signature as a header or payload field.
   */
  signEventPayload(payload: Record<string, unknown>): string {
    const canonical = JSON.stringify(payload);
    return crypto
      .createHmac('sha256', this.apiKey)
      .update(canonical)
      .digest('hex');
  }

  /**
   * Verify an event payload signature (anti-tampering check).
   */
  verifyEventSignature(
    payload: Record<string, unknown>,
    signature: string
  ): boolean {
    const canonical = JSON.stringify(payload);
    const expected = crypto
      .createHmac('sha256', this.apiKey)
      .update(canonical)
      .digest('hex');

    const sigBuffer = Buffer.from(signature, 'hex');
    const expectedBuffer = Buffer.from(expected, 'hex');

    if (sigBuffer.length !== expectedBuffer.length) return false;
    return crypto.timingSafeEqual(sigBuffer, expectedBuffer);
  }

  // ── Private Helpers ───────────────────────────────────────

  /**
   * S28: Check webhook endpoint rate limit (flooding protection).
   * Returns true if delivery is allowed, false if rate limited.
   */
  private checkWebhookRateLimit(endpointUrl: string): boolean {
    const now = Date.now();
    const bucket = this.webhookDeliveryCounts.get(endpointUrl);

    if (
      !bucket ||
      now - bucket.windowStart >= DevFortressCore.WEBHOOK_RATE_WINDOW_MS
    ) {
      this.webhookDeliveryCounts.set(endpointUrl, {
        count: 1,
        windowStart: now,
      });
      return true;
    }

    if (bucket.count >= DevFortressCore.WEBHOOK_RATE_LIMIT) {
      return false;
    }

    bucket.count++;
    return true;
  }

  private async sendWithRetry(
    payload: Record<string, unknown>,
    attempt: number = 1
  ): Promise<{ data: ApiResponse }> {
    try {
      const response = await this.axios.post('', payload);
      return response;
    } catch (error) {
      const axiosError = error as AxiosError;
      if (axiosError.response?.status && axiosError.response.status < 500) {
        throw error;
      }
      if (attempt < this.retries) {
        const backoff = Math.pow(2, attempt) * 1000;
        await new Promise(resolve => setTimeout(resolve, backoff));
        return this.sendWithRetry(payload, attempt + 1);
      }
      throw error;
    }
  }

  protected log(
    level: 'info' | 'warn' | 'error' | 'debug',
    message: string
  ): void {
    if (!this.debug && level === 'debug') return;
    const prefix = '[DevFortress]';
    switch (level) {
      case 'error':
        console.error(`${prefix} ${message}`);
        break;
      case 'warn':
        console.warn(`${prefix} ${message}`);
        break;
      case 'debug':
      case 'info':
        if (this.debug) {
          console.log(`${prefix} ${message}`);
        }
        break;
    }
  }
}
