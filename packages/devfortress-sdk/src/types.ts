/**
 * DevFortress SDK v3.0.0 — Type Definitions
 *
 * Covers:
 * - Event types & severity levels
 * - SDK configuration & enrichment hooks
 * - Threat events & webhook payloads
 * - Credential isolation interfaces
 * - AbuseIPDB types
 */

// ── Closed-Loop Mode ────────────────────────────────────────

/** Closed-loop protection mode:
 * - 'external': SDK → DevFortress Platform → webhook → response (default)
 * - 'internal': 3-tier local engine, no platform calls (enterprise/air-gap)
 * - 'hybrid':   Internal evaluates first, external enriches asynchronously
 */
export type CLMode = 'external' | 'internal' | 'hybrid';

// ── Event & Severity ────────────────────────────────────────

export type EventType =
  | 'auth_failure'
  | 'validation_error'
  | 'rate_limit_exceeded'
  | '5xx_error'
  | '4xx_error'
  | 'suspicious_pattern'
  | 'sql_injection_attempt'
  | 'xss_attempt'
  | 'custom'
  // v3.0 pre-auth threat types
  | 'login_brute_force'
  | 'credential_stuffing'
  | 'password_spray'
  | 'honeypot_triggered'
  | 'sql_injection'
  | 'auth_endpoint_scan'
  | 'recon_scan'
  | 'bot_signature'
  // v3.0 post-auth threat types
  | 'brute_force'
  | 'token_replay'
  | 'privilege_escalation'
  | 'suspicious_ip'
  | 'anomalous_volume'
  | 'geo_anomaly';

export type SeverityLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type ThreatSeverity = 'low' | 'medium' | 'high' | 'critical';

// ── Auth Phase ───────────────────────────────────────────────

/** Authentication phase when the event occurred:
 * - 'pre_auth':  Before authentication (login attempts, public endpoint attacks)
 * - 'post_auth': After authentication (session-based threats, privilege escalation)
 */
export type AuthPhase = 'pre_auth' | 'post_auth';

/** Action taken by the protection system in response to the threat */
export type ActionTaken =
  | 'blocked'
  | 'rate_limited'
  | 'session_revoked'
  | 'captcha_challenged'
  | 'challenge_required'
  | 'flagged'
  | 'allowed'
  | 'monitored';

/** Security arm that processed the event */
export type SecurityArm = 'collect' | 'detect' | 'respond' | 'patch';

// ── Live Threat Event (SDK → Platform) ──────────────────────

export interface LiveThreatEvent {
  eventType: EventType;
  timestamp?: string;
  ip: string;
  method: string;
  path: string;
  userAgent?: string | null;
  statusCode?: number | null;
  responseTime?: number | null;
  metadata?: Record<string, unknown>;
  severity: SeverityLevel;
  reason?: string;
  // v3.0 enrichment fields
  userId?: string | null;
  sessionId?: string | null;
  appId?: string;
  environment?: string;
  compositeScore?: number;
  abuseipdb?: AbuseIPDBScore;
  // v3.1 observability fields — dashboard proof points (mandatory since v4.3)
  /** Closed-loop protection mode active when event was captured */
  clMode: CLMode;
  /** Whether event occurred pre-auth or post-auth */
  authPhase: AuthPhase;
  /** Action taken by the protection system */
  actionTaken: ActionTaken;
  /** Response latency in milliseconds (time from request to SDK event emission) */
  responseLatencyMs: number;
  /** Security arm that processed the event (collect, detect, respond, patch) */
  securityArm?: SecurityArm;
  /** Whether user session remained active after the action was taken */
  sessionActiveAfterAction?: boolean;
  // v4.0 agentic security fields
  /** Identifies if the event originated from an AI agent */
  isAgent?: boolean;
  /** Unique identifier for the AI agent (e.g., LangChain agent ID) */
  agentId?: string;
  /** Type of AI agent (e.g., 'langchain', 'openai', 'anthropic', 'custom') */
  agentType?: string;
}

// ── Client Configuration ────────────────────────────────────

export interface DevFortressClientOptions {
  apiKey: string;
  endpoint?: string;
  timeout?: number;
  retries?: number;
  debug?: boolean;
  /** Max events per batch when batching is enabled (default: 25, server max: 100) */
  batchSize?: number;
  /** Milliseconds between automatic flush of buffered events (default: 5000) */
  flushIntervalMs?: number;
}

// ── v3.0 Full Configuration ─────────────────────────────────

export interface DevFortressConfig {
  apiKey: string;
  appId: string;
  environment?: string;
  debug?: boolean;
  endpoint?: string;
  timeout?: number;
  retries?: number;
  enrichment?: EnrichmentConfig;
  alertThresholds?: Partial<Record<string, ThreatSeverity>>;
  responseWebhook?: {
    url: string;
    secret: string;
    /**
     * A4 nonce-based replay prevention is mandatory by default: any inbound
     * webhook missing a `nonce` field is rejected. Set true only to permit
     * legacy senders that predate nonce support — HMAC signature + timestamp
     * checks still apply either way. Default: false.
     */
    allowLegacyUnsignedWebhooks?: boolean;
  };
  cache?: {
    driver: 'redis' | 'memory';
    url?: string;
    ttl?: number;
  };
  /** Closed-loop protection mode. Default: 'external' */
  mode?: CLMode;
  /** When true, isBlocked() returns true on network errors (fail-closed).
   *  When false (default), isBlocked() returns false on errors (fail-open). */
  failClosed?: boolean;
  /** Subscription tier for feature gating */
  tier?: 'starter' | 'pro' | 'team' | 'enterprise';
  /** Whether the hybrid add-on is enabled (Pro tier only) */
  hybridAddonEnabled?: boolean;
  /** Internal closed-loop engine configuration (for 'internal' or 'hybrid' mode) */
  internalCL?: {
    /** Fail-closed (block on error) or fail-open. Default: 'closed' */
    failMode?: 'closed' | 'open';
    /** Custom Tier 2 scorer. If omitted on a tier with ICL Tier 2 access
     *  (Team/Enterprise), defaults to the embedded MLClassifier. */
    tier2Scorer?: (request: unknown) => Promise<number> | number;
    /** Score threshold for auto-block. Default: 85 */
    blockThreshold?: number;
    /** Rate limit: max requests per window. Default: 100 */
    rateLimitMax?: number;
    /** Rate limit window in ms. Default: 60000 */
    rateLimitWindowMs?: number;
  };
  /** Circuit breaker config for hybrid mode fallback */
  circuitBreaker?: {
    /** Failures before opening circuit. Default: 3 */
    failureThreshold?: number;
    /** Time before testing recovery in ms. Default: 60000 */
    recoveryTimeMs?: number;
  };
  /** License validation config (CV-M1). Set enabled: false to disable. */
  license?: {
    /** Enable license validation. Default: true */
    enabled?: boolean;
    /** License check interval in ms. Default: 86400000 (24h) */
    checkIntervalMs?: number;
    /** Grace period before degradation in ms. Default: 259200000 (72h) */
    gracePeriodMs?: number;
  };
  /** Telemetry heartbeat config (CV-M2). Set enabled: false to disable. */
  telemetry?: {
    /** Enable telemetry heartbeat. Default: true */
    enabled?: boolean;
    /** Heartbeat interval in ms. Default: 300000 (5min) */
    heartbeatIntervalMs?: number;
  };
  // DevFortressFullConfig in src/agent-identity/devfortress-full.ts (that
  // file, and its built output, are excluded from the published package;
  // keeping these fields off this shared, published config type prevents
  // published dist/types.d.ts).
}

export interface EnrichmentConfig {
  getUserId?: (req: unknown) => string | null | Promise<string | null>;
  getSessionId?: (req: unknown) => string | null | Promise<string | null>;
  getIP?: (req: unknown) => string | null;
}

// ── Observe Result ──────────────────────────────────────────

export interface ObserveResult {
  flagged: boolean;
  event_id: string;
  confidence: number;
}

export interface ObserveOptions {
  meta?: Record<string, unknown>;
  skipEnrichment?: boolean;
}

// ── Threat Event (Platform → Client App via webhook) ────────

export interface ThreatEvent {
  event_id: string;
  threat_type: string;
  severity: ThreatSeverity;
  confidence: number;
  composite_score: number;
  ip: string;
  identity: {
    user_id: string | null;
    session_id: string | null;
  };
  geo?: {
    country: string;
    city: string;
  };
  abuseipdb?: AbuseIPDBScore;
  endpoint: string;
  method: string;
  timestamp: string;
  meta: Record<string, unknown>;
}

// ── Action Confirmation ─────────────────────────────────────

export interface ActionReport {
  success: boolean;
  actions: string[];
  reason?: string;
  meta?: Record<string, unknown>;
}

// ── AbuseIPDB ───────────────────────────────────────────────

export interface AbuseIPDBScore {
  score: number;
  isTor: boolean;
  isDatacenter: boolean;
  distinctUsers?: number;
  fromCache?: boolean;
}

export interface AbuseIPDBCheckResult {
  abuseConfidenceScore: number;
  totalReports: number;
  numDistinctUsers: number;
  isTor: boolean;
  usageType: string;
  countryCode: string;
  lastReportedAt: string | null;
  isp: string;
}

export interface CompositeScoreResult {
  score: number;
  severity: ThreatSeverity;
  abuseScore: number;
  isTor: boolean;
  isDatacenter: boolean;
  distinctUsers: number;
  fromCache: boolean;
}

// ── Credential Isolation ────────────────────────────────────

export interface IsolatedCredentialData {
  realToken: string;
  userId: string;
  createdAt: number;
}

// ── Middleware Options ───────────────────────────────────────

export interface DevFortressMiddlewareOptions extends DevFortressClientOptions {
  captureBody?: boolean;
  captureHeaders?: boolean;
  excludePaths?: string[];
  sanitize?: (data: Record<string, unknown>) => Record<string, unknown>;
  onRequest?: (req: unknown) => Partial<LiveThreatEvent> | null;
  onError?: (error: Error) => void;
  mode?: CLMode;
}

// ── API Response ────────────────────────────────────────────

export interface ApiResponse {
  success: boolean;
  message?: string;
  eventId?: string;
  /** Batch-mode fields */
  processed?: number;
  successful?: number;
  failed?: number;
  results?: Array<{ success: boolean; eventId?: string; error?: string }>;
}

// ── Webhook Payload ─────────────────────────────────────────

export interface WebhookPayload {
  event_id: string;
  action: string;
  threat_type: string;
  severity: ThreatSeverity;
  confidence: number;
  composite_score: number;
  ip: string;
  identity: {
    user_id: string | null;
    session_id: string | null;
  };
  geo?: {
    country: string;
    city: string;
  };
  abuseipdb?: AbuseIPDBScore;
  endpoint: string;
  method: string;
  timestamp: string;
  meta: Record<string, unknown>;
}

// ── Threat Handler ──────────────────────────────────────────

export type ThreatHandler = (event: ThreatEvent) => Promise<void> | void;
