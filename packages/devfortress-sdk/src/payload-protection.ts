/**
 *
 * Secures the actual data payloads exchanged between client applications
 * and third-party services — ensuring integrity, authenticity, and
 * confidentiality of data in transit beyond the SDK–platform boundary.
 *
 * Three-layer architecture:
 *   Layer 1: Outbound payload signing + selective field encryption
 *   Layer 2: Inbound response verification + schema baseline
 *   Layer 3: Bidirectional audit trail + anomaly detection
 *
 * Signing identity reinforcement options:
 *   - appId:     per-application signing key
 *   - userId:    per-user signing context (session-scoped)
 *   - browserId: browser fingerprint binding (web clients)
 *   - deviceId:  device attestation binding (mobile/desktop)
 *
 * @packageDocumentation
 */

import crypto from 'crypto';

// ── Types ───────────────────────────────────────────────────

export type PayloadDirection = 'outbound' | 'inbound';

export interface PayloadProtectionConfig {
  /** Application signing key (derived from DevFortress credential). */
  appSigningKey: string;
  /** Application identifier for attestation headers. */
  appId: string;
  /** Enable outbound payload signing. Default: true */
  signOutbound?: boolean;
  /** Enable inbound response verification. Default: true */
  verifyInbound?: boolean;
  /** Enable selective field encryption. Default: false */
  selectiveEncryption?: boolean;
  /** PII field patterns for selective encryption (regex strings). */
  piiPatterns?: string[];
  /** Enable response freshness verification. Default: true */
  freshnessCheck?: boolean;
  /** Maximum acceptable response age in ms. Default: 30_000 (30s) */
  maxResponseAgeMs?: number;
  /** Enable certificate pinning for known services. Default: true */
  certPinning?: boolean;
  /** Enable anomaly detection on payload traffic. Default: true */
  anomalyDetection?: boolean;
  /** Volume anomaly threshold (requests per minute). Default: 100 */
  volumeAnomalyThreshold?: number;
  /** Payload size deviation threshold (std deviations). Default: 3.0 */
  sizeAnomalyStdDevs?: number;
  /** Latency anomaly threshold (std deviations). Default: 3.0 */
  latencyAnomalyStdDevs?: number;
  /** Enable circuit breaker for suspicious third-parties. Default: true */
  circuitBreaker?: boolean;
  /** Circuit breaker trip threshold (anomalies before trip). Default: 5 */
  circuitBreakerThreshold?: number;
  /** Circuit breaker reset timeout in ms. Default: 60_000 (1 min) */
  circuitBreakerResetMs?: number;
  /** Max audit log entries. Default: 10_000 */
  maxAuditEntries?: number;
  debug?: boolean;
}

export interface SigningContext {
  /** Application ID — always included. */
  appId: string;
  /** User ID — per-user signing context (session-scoped). */
  userId?: string;
  /** Browser ID — fingerprint binding for web clients. */
  browserId?: string;
  /** Device ID — attestation binding for mobile/desktop. */
  deviceId?: string;
  aliasId?: string;
  /** Timestamp override (for testing). */
  timestamp?: number;
}

export interface PayloadAttestation {
  /** Base64-encoded HMAC signature of the payload + context. */
  signature: string;
  /** Epoch milliseconds when attestation was generated. */
  timestamp: number;
  /** Canonical hash of the payload. */
  payloadHash: string;
  /** Application identifier. */
  appId: string;
  aliasId?: string;
  /** Signing context identifiers included in the attestation. */
  contextIds: string[];
}

export interface FieldEncryptionResult {
  /** The payload with sensitive fields encrypted. */
  encryptedPayload: Record<string, unknown>;
  /** Map of field paths → encryption metadata. */
  encryptedFields: Map<string, EncryptedFieldMeta>;
  /** Number of fields encrypted. */
  fieldCount: number;
}

export interface EncryptedFieldMeta {
  /** Original field path (dot notation). */
  fieldPath: string;
  /** Encryption algorithm used. */
  algorithm: string;
  /** Initialization vector (hex). */
  iv: string;
  /** Auth tag (hex) for AES-GCM. */
  authTag: string;
}

export interface ResponseVerificationResult {
  /** Whether the response passes integrity checks. */
  valid: boolean;
  /** Hash of the response payload. */
  payloadHash: string;
  /** Schema conformance result (if baseline available). */
  schemaConforms?: boolean;
  /** Whether response freshness check passed. */
  freshnessValid?: boolean;
  /** Certificate pin match result. */
  certPinValid?: boolean;
  /** List of detected injection indicators. */
  injectionIndicators: string[];
  /** Response latency in ms. */
  latencyMs?: number;
  /** Anomaly details (if any). */
  anomalies: PayloadAnomaly[];
}

export interface PayloadAnomaly {
  /** Type of anomaly detected. */
  type:
    | 'volume_spike'
    | 'schema_drift'
    | 'latency_spike'
    | 'size_anomaly'
    | 'injection_detected'
    | 'freshness_expired'
    | 'cert_pin_mismatch';
  /** Severity: low, medium, high, critical. */
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** Human-readable description. */
  description: string;
  /** Observed value. */
  observed?: number;
  /** Expected/baseline value. */
  expected?: number;
}

export interface PayloadAuditEntry {
  /** Direction: outbound or inbound. */
  direction: PayloadDirection;
  /** Third-party service identifier. */
  thirdPartyId: string;
  /** Payload hash (not the payload itself). */
  payloadHash: string;
  aliasId?: string;
  /** Signing context identifiers. */
  contextIds: string[];
  /** HTTP status code (inbound only). */
  statusCode?: number;
  /** Response latency in ms. */
  latencyMs?: number;
  /** Schema conformance result. */
  schemaConforms?: boolean;
  /** Anomalies detected. */
  anomalies: PayloadAnomaly[];
  /** Timestamp. */
  timestamp: number;
  /** Payload size in bytes. */
  payloadSizeBytes: number;
}

export interface PayloadProtectionStats {
  /** Total outbound requests signed. */
  outboundSigned: number;
  /** Total inbound responses verified. */
  inboundVerified: number;
  /** Total fields encrypted. */
  fieldsEncrypted: number;
  /** Total anomalies detected. */
  anomaliesDetected: number;
  /** Circuit breakers currently tripped. */
  circuitBreakersTripped: number;
  /** Per-service stats. */
  byService: Map<string, ServicePayloadStats>;
}

export interface ServicePayloadStats {
  /** Service identifier. */
  serviceId: string;
  /** Total requests. */
  requestCount: number;
  /** Running mean payload size. */
  meanPayloadSize: number;
  /** Running std dev of payload size. */
  stdDevPayloadSize: number;
  /** Running mean latency. */
  meanLatency: number;
  /** Running std dev of latency. */
  stdDevLatency: number;
  /** Requests per minute (sliding window). */
  requestsPerMinute: number;
  /** Circuit breaker state. */
  circuitState: 'closed' | 'open' | 'half-open';
  /** Known certificate fingerprint. */
  certFingerprint?: string;
}

// ── Internal EWMA tracker ───────────────────────────────────

interface EWMATracker {
  mean: number;
  variance: number;
  count: number;
}

function updateEWMA(tracker: EWMATracker, value: number, alpha = 0.1): void {
  if (tracker.count === 0) {
    tracker.mean = value;
    tracker.variance = 0;
    tracker.count = 1;
    return;
  }
  const diff = value - tracker.mean;
  tracker.mean += alpha * diff;
  tracker.variance = (1 - alpha) * (tracker.variance + alpha * diff * diff);
  tracker.count++;
}

function ewmaStdDev(tracker: EWMATracker): number {
  return Math.sqrt(Math.max(tracker.variance, 0));
}

// ── Default PII patterns ────────────────────────────────────

const DEFAULT_PII_PATTERNS = [
  'email',
  'phone',
  'ssn',
  'social.?security',
  'credit.?card',
  'card.?number',
  'cvv',
  'password',
  'secret',
  'token',
  'api.?key',
  'date.?of.?birth',
  'dob',
  'address',
  'passport',
  'national.?id',
];

// ── Injection patterns for response scanning ────────────────

const INJECTION_PATTERNS = [
  /<script[\s>]/i,
  /javascript:/i,
  /on(?:error|load|click|mouseover)=/i,
  // Bounded gap (not `\s+.*\s+`, which is polynomial: `.*` can itself match
  // whitespace, so the engine retries every split between it and the
  // trailing `\s+` on input that never resolves to FROM). The `{1,500}`
  // caps backtracking to a constant regardless of input length.
  /SELECT\s+[\s\S]{1,500}?\s+FROM\s+/i,
  /UNION\s+(?:ALL\s+)?SELECT/i,
  /INSERT\s+INTO/i,
  /DROP\s+TABLE/i,
  /;\s*(?:DELETE|UPDATE|ALTER|CREATE)\s+/i,
  /http:\/\/127\.0\.0\.1/i,
  /http:\/\/localhost/i,
  /http:\/\/169\.254\./i,
  /http:\/\/0\.0\.0\.0/i,
  /file:\/\//i,
  /;\s*rm\s+-rf/i,
  /\$\([^)]*\)/,
  /`[^`]*`/,
  /;\s*(?:cat|wget|curl|nc|bash|sh)\s+/i,
  /\|\s*(?:nc|bash|sh)\b/i,
  /\.\.\//,
  /\.\.\\/,
  /%2e%2e%2f/i,
  /\/etc\/(?:passwd|shadow)/i,
];

/** Hard cap on bytes scanned per response by {@link INJECTION_PATTERNS}. */
const MAX_INJECTION_SCAN_LENGTH = 100_000;

/** Path segments that would reach Object.prototype via bracket assignment. */
const UNSAFE_PATH_SEGMENTS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Patent Pending — KIPI KE/P/2026/005972
 * Prior art: https://www.tdcommons.org/dpubs_series/9907/
 */
export class PayloadProtectionService {
  private readonly config: Required<PayloadProtectionConfig>;
  private readonly auditLog: PayloadAuditEntry[] = [];
  private readonly serviceStats = new Map<
    string,
    {
      sizeTracker: EWMATracker;
      latencyTracker: EWMATracker;
      requestTimestamps: number[];
      circuitState: 'closed' | 'open' | 'half-open';
      circuitOpenedAt: number;
      anomalyCount: number;
      certFingerprint?: string;
      responseSchemaBaseline?: Record<string, string>;
    }
  >();
  private readonly piiRegexes: RegExp[];

  // Counters
  private outboundSigned = 0;
  private inboundVerified = 0;
  private fieldsEncrypted = 0;
  private anomaliesDetected = 0;

  constructor(config: PayloadProtectionConfig) {
    const piiPatterns = config.piiPatterns ?? DEFAULT_PII_PATTERNS;
    this.config = {
      appSigningKey: config.appSigningKey,
      appId: config.appId,
      signOutbound: config.signOutbound ?? true,
      verifyInbound: config.verifyInbound ?? true,
      selectiveEncryption: config.selectiveEncryption ?? false,
      piiPatterns: piiPatterns,
      freshnessCheck: config.freshnessCheck ?? true,
      maxResponseAgeMs: config.maxResponseAgeMs ?? 30_000,
      certPinning: config.certPinning ?? true,
      anomalyDetection: config.anomalyDetection ?? true,
      volumeAnomalyThreshold: config.volumeAnomalyThreshold ?? 100,
      sizeAnomalyStdDevs: config.sizeAnomalyStdDevs ?? 3.0,
      latencyAnomalyStdDevs: config.latencyAnomalyStdDevs ?? 3.0,
      circuitBreaker: config.circuitBreaker ?? true,
      circuitBreakerThreshold: config.circuitBreakerThreshold ?? 5,
      circuitBreakerResetMs: config.circuitBreakerResetMs ?? 60_000,
      maxAuditEntries: config.maxAuditEntries ?? 10_000,
      debug: config.debug ?? false,
    };

    this.piiRegexes = piiPatterns.map(p => new RegExp(p, 'i'));
  }

  // ── Layer 1: Outbound Payload Signing ───────────────────

  /**
   * Compute a canonical hash of a JSON payload.
   * Uses deterministic JSON serialization (sorted keys) to ensure
   * identical payloads produce identical hashes regardless of key order.
   */
  canonicalHash(payload: unknown): string {
    const canonical = this.canonicalize(payload);
    return crypto.createHash('sha256').update(canonical).digest('hex');
  }

  /**
   * Sign an outbound payload with the application signing key and
   * additional signing context (userId, browserId, deviceId).
   *
   * Returns an attestation object to attach as request headers.
   */
  signOutboundPayload(
    payload: unknown,
    context: SigningContext
  ): PayloadAttestation {
    const timestamp = context.timestamp ?? Date.now();
    const payloadHash = this.canonicalHash(payload);

    // Build signing input: aliasId + appId + userId + browserId + deviceId + timestamp + payloadHash
    const contextIds: string[] = [context.appId];
    const signingParts: string[] = [
      context.appId,
      String(timestamp),
      payloadHash,
    ];

    if (context.aliasId) {
      signingParts.push(context.aliasId);
      contextIds.push(`alias:${context.aliasId}`);
    }
    if (context.userId) {
      signingParts.push(context.userId);
      contextIds.push(`user:${context.userId}`);
    }
    if (context.browserId) {
      signingParts.push(context.browserId);
      contextIds.push(`browser:${context.browserId}`);
    }
    if (context.deviceId) {
      signingParts.push(context.deviceId);
      contextIds.push(`device:${context.deviceId}`);
    }

    const signingInput = signingParts.join('|');
    const signature = crypto
      .createHmac('sha256', this.config.appSigningKey)
      .update(signingInput)
      .digest('base64');

    this.outboundSigned++;

    if (this.config.debug) {
      console.log(
        `[PayloadProtection] Signed outbound: hash=${payloadHash.substring(0, 16)}... ctx=[${contextIds.join(',')}]`
      );
    }

    return {
      signature,
      timestamp,
      payloadHash,
      appId: context.appId,
      aliasId: context.aliasId,
      contextIds,
    };
  }

  /**
   * Verify an attestation header against the received payload.
   * Used by receiving parties that support DevFortress verification.
   */
  verifyAttestation(
    payload: unknown,
    attestation: PayloadAttestation,
    context: SigningContext
  ): boolean {
    const payloadHash = this.canonicalHash(payload);
    if (payloadHash !== attestation.payloadHash) return false;

    // Reconstruct signing input
    const signingParts: string[] = [
      context.appId,
      String(attestation.timestamp),
      payloadHash,
    ];
    if (context.aliasId) signingParts.push(context.aliasId);
    if (context.userId) signingParts.push(context.userId);
    if (context.browserId) signingParts.push(context.browserId);
    if (context.deviceId) signingParts.push(context.deviceId);

    const signingInput = signingParts.join('|');
    const expectedSig = crypto
      .createHmac('sha256', this.config.appSigningKey)
      .update(signingInput)
      .digest('base64');

    return crypto.timingSafeEqual(
      Buffer.from(attestation.signature, 'base64'),
      Buffer.from(expectedSig, 'base64')
    );
  }

  // ── Layer 1b: Selective Field Encryption ────────────────

  /**
   * Encrypt sensitive fields in a payload before outbound transmission.
   * Uses AES-256-GCM with a session-scoped key derived from the
   * signing key + third-party ID + alias ID.
   */
  encryptSensitiveFields(
    payload: Record<string, unknown>,
    thirdPartyId: string,
    aliasId?: string
  ): FieldEncryptionResult {
    const encryptedPayload = { ...payload };
    const encryptedFields = new Map<string, EncryptedFieldMeta>();
    let fieldCount = 0;

    // Derive per-session, per-third-party encryption key
    const fieldKey = this.deriveFieldKey(thirdPartyId, aliasId);
    const aadContext = this.buildAADContext(thirdPartyId, aliasId);

    this.walkAndEncrypt(
      encryptedPayload,
      '',
      fieldKey,
      encryptedFields,
      aadContext
    );
    fieldCount = encryptedFields.size;
    this.fieldsEncrypted += fieldCount;

    return { encryptedPayload, encryptedFields, fieldCount };
  }

  /**
   * Decrypt sensitive fields from an inbound payload.
   *
   * Fails closed: if a field's AES-GCM auth tag doesn't verify against its
   * bound AAD (thirdPartyId|aliasId|fieldPath), this throws rather than
   * leaving the ciphertext in place — a mismatch means either the ciphertext
   * was swapped between fields/records or the payload was tampered with.
   */
  decryptSensitiveFields(
    payload: Record<string, unknown>,
    encryptedFields: Map<string, EncryptedFieldMeta>,
    thirdPartyId: string,
    aliasId?: string
  ): Record<string, unknown> {
    const decrypted = { ...payload };
    const fieldKey = this.deriveFieldKey(thirdPartyId, aliasId);
    const aadContext = this.buildAADContext(thirdPartyId, aliasId);

    for (const [fieldPath, meta] of encryptedFields) {
      const value = this.getNestedValue(decrypted, fieldPath);
      if (typeof value === 'string') {
        const decipher = crypto.createDecipheriv(
          'aes-256-gcm',
          fieldKey,
          Buffer.from(meta.iv, 'hex')
        );
        decipher.setAAD(
          Buffer.from(this.buildFieldAAD(aadContext, fieldPath), 'utf8')
        );
        decipher.setAuthTag(Buffer.from(meta.authTag, 'hex'));
        let decryptedValue: string;
        try {
          decryptedValue = decipher.update(value, 'hex', 'utf8');
          decryptedValue += decipher.final('utf8');
        } catch {
          throw new Error(
            `[PayloadProtection] Field decryption failed for "${fieldPath}": AAD/auth tag verification failed — possible field-swap or ciphertext tampering`
          );
        }
        this.setNestedValue(decrypted, fieldPath, decryptedValue);
      }
    }

    return decrypted;
  }

  // ── Layer 2: Inbound Response Verification ──────────────

  /**
   * Verify an inbound response from a third-party service.
   * Checks: integrity, schema conformance, freshness, injection,
   * certificate pin, and anomalies.
   */
  verifyInboundResponse(
    responsePayload: unknown,
    thirdPartyId: string,
    options?: {
      statusCode?: number;
      latencyMs?: number;
      responseDate?: string;
      certFingerprint?: string;
      aliasId?: string;
      signingContext?: SigningContext;
    }
  ): ResponseVerificationResult {
    const now = Date.now();
    const payloadHash = this.canonicalHash(responsePayload);
    const anomalies: PayloadAnomaly[] = [];
    const injectionIndicators: string[] = [];

    // Get or create service stats
    const stats = this.getOrCreateServiceStats(thirdPartyId);

    // 1. Injection scan
    const payloadStr =
      typeof responsePayload === 'string'
        ? responsePayload
        : JSON.stringify(responsePayload);
    // Defense in depth: bound what the regex scan below ever sees, even
    // after the pattern-level fix, so an unexpectedly huge third-party
    // response can't inflate scan time.
    const scanStr =
      payloadStr.length > MAX_INJECTION_SCAN_LENGTH
        ? payloadStr.slice(0, MAX_INJECTION_SCAN_LENGTH)
        : payloadStr;

    for (const pattern of INJECTION_PATTERNS) {
      if (pattern.test(scanStr)) {
        injectionIndicators.push(pattern.source);
      }
    }
    if (injectionIndicators.length > 0) {
      anomalies.push({
        type: 'injection_detected',
        severity: 'critical',
        description: `Injection indicators found: ${injectionIndicators.join(', ')}`,
      });
    }

    // 2. Freshness verification
    let freshnessValid: boolean | undefined;
    if (this.config.freshnessCheck && options?.responseDate) {
      const responseTime = new Date(options.responseDate).getTime();
      const age = now - responseTime;
      freshnessValid = age <= this.config.maxResponseAgeMs && age >= -5000;
      if (!freshnessValid) {
        anomalies.push({
          type: 'freshness_expired',
          severity: 'medium',
          description: `Response age ${age}ms exceeds max ${this.config.maxResponseAgeMs}ms`,
          observed: age,
          expected: this.config.maxResponseAgeMs,
        });
      }
    }

    // 3. Certificate pin verification
    let certPinValid: boolean | undefined;
    if (this.config.certPinning && options?.certFingerprint) {
      if (stats.certFingerprint) {
        certPinValid = stats.certFingerprint === options.certFingerprint;
        if (!certPinValid) {
          anomalies.push({
            type: 'cert_pin_mismatch',
            severity: 'critical',
            description: `Certificate fingerprint mismatch for ${thirdPartyId}`,
          });
        }
      } else {
        // First connection — pin the certificate
        stats.certFingerprint = options.certFingerprint;
        certPinValid = true;
      }
    }

    // 4. Schema baseline drift detection
    let schemaConforms: boolean | undefined;
    if (responsePayload && typeof responsePayload === 'object') {
      const currentSchema = this.extractSchemaSignature(
        responsePayload as Record<string, unknown>
      );
      if (stats.responseSchemaBaseline) {
        const drifts = this.compareSchemas(
          stats.responseSchemaBaseline,
          currentSchema
        );
        schemaConforms = drifts.length === 0;
        if (!schemaConforms) {
          anomalies.push({
            type: 'schema_drift',
            severity: 'medium',
            description: `Schema drift in ${drifts.length} fields: ${drifts.slice(0, 3).join(', ')}`,
          });
        }
      } else {
        // First response — establish baseline
        stats.responseSchemaBaseline = currentSchema;
        schemaConforms = true;
      }
    }

    // 5. Anomaly detection
    if (this.config.anomalyDetection) {
      // Payload size anomaly
      const payloadSize = Buffer.byteLength(payloadStr, 'utf8');
      updateEWMA(stats.sizeTracker, payloadSize);
      if (stats.sizeTracker.count > 10) {
        const stdDev = ewmaStdDev(stats.sizeTracker);
        const zScore =
          stdDev > 0
            ? Math.abs(payloadSize - stats.sizeTracker.mean) / stdDev
            : 0;
        if (zScore > this.config.sizeAnomalyStdDevs) {
          anomalies.push({
            type: 'size_anomaly',
            severity: 'medium',
            description: `Payload size ${payloadSize}B deviates ${zScore.toFixed(1)}σ from mean ${stats.sizeTracker.mean.toFixed(0)}B`,
            observed: payloadSize,
            expected: stats.sizeTracker.mean,
          });
        }
      }

      // Latency anomaly
      if (options?.latencyMs !== undefined) {
        updateEWMA(stats.latencyTracker, options.latencyMs);
        if (stats.latencyTracker.count > 10) {
          const stdDev = ewmaStdDev(stats.latencyTracker);
          const zScore =
            stdDev > 0
              ? Math.abs(options.latencyMs - stats.latencyTracker.mean) / stdDev
              : 0;
          if (zScore > this.config.latencyAnomalyStdDevs) {
            anomalies.push({
              type: 'latency_spike',
              severity: 'medium',
              description: `Latency ${options.latencyMs}ms deviates ${zScore.toFixed(1)}σ from mean ${stats.latencyTracker.mean.toFixed(0)}ms`,
              observed: options.latencyMs,
              expected: stats.latencyTracker.mean,
            });
          }
        }
      }

      // Volume anomaly (requests per minute)
      stats.requestTimestamps.push(now);
      const oneMinuteAgo = now - 60_000;
      const idx = stats.requestTimestamps.findIndex(t => t > oneMinuteAgo);
      if (idx > 0) stats.requestTimestamps.splice(0, idx);
      const rpm = stats.requestTimestamps.length;
      if (rpm > this.config.volumeAnomalyThreshold) {
        anomalies.push({
          type: 'volume_spike',
          severity: 'high',
          description: `${rpm} requests/min to ${thirdPartyId} exceeds threshold ${this.config.volumeAnomalyThreshold}`,
          observed: rpm,
          expected: this.config.volumeAnomalyThreshold,
        });
      }
    }

    // 6. Circuit breaker check
    if (this.config.circuitBreaker && anomalies.length > 0) {
      stats.anomalyCount += anomalies.length;
      this.anomaliesDetected += anomalies.length;

      if (
        stats.anomalyCount >= this.config.circuitBreakerThreshold &&
        stats.circuitState === 'closed'
      ) {
        stats.circuitState = 'open';
        stats.circuitOpenedAt = now;
        if (this.config.debug) {
          console.log(
            `[PayloadProtection] Circuit breaker OPENED for ${thirdPartyId} — ${stats.anomalyCount} anomalies`
          );
        }
      }
    }

    this.inboundVerified++;

    // Record audit entry
    const payloadSize = Buffer.byteLength(payloadStr, 'utf8');
    this.recordAudit({
      direction: 'inbound',
      thirdPartyId,
      payloadHash,
      aliasId: options?.aliasId,
      contextIds: options?.signingContext?.appId
        ? [options.signingContext.appId]
        : [],
      statusCode: options?.statusCode,
      latencyMs: options?.latencyMs,
      schemaConforms,
      anomalies,
      timestamp: now,
      payloadSizeBytes: payloadSize,
    });

    return {
      valid:
        anomalies.filter(
          a => a.severity === 'critical' || a.severity === 'high'
        ).length === 0,
      payloadHash,
      schemaConforms,
      freshnessValid,
      certPinValid,
      injectionIndicators,
      latencyMs: options?.latencyMs,
      anomalies,
    };
  }

  // ── Layer 3: Circuit Breaker ────────────────────────────

  /**
   * Check if a third-party service is currently blocked by the circuit breaker.
   */
  isCircuitOpen(thirdPartyId: string): boolean {
    const stats = this.serviceStats.get(thirdPartyId);
    if (!stats) return false;

    if (stats.circuitState === 'open') {
      // Check if reset timeout has elapsed
      if (
        Date.now() - stats.circuitOpenedAt >=
        this.config.circuitBreakerResetMs
      ) {
        stats.circuitState = 'half-open';
        return false; // Allow a probe request
      }
      return true;
    }

    return false;
  }

  /**
   * Reset the circuit breaker for a third-party service.
   */
  resetCircuitBreaker(thirdPartyId: string): void {
    const stats = this.serviceStats.get(thirdPartyId);
    if (stats) {
      stats.circuitState = 'closed';
      stats.anomalyCount = 0;
    }
  }

  // ── Layer 3: Audit Trail ────────────────────────────────

  /**
   * Record an outbound payload in the audit trail.
   */
  recordOutboundAudit(
    thirdPartyId: string,
    payloadHash: string,
    context: SigningContext,
    payloadSizeBytes: number
  ): void {
    this.recordAudit({
      direction: 'outbound',
      thirdPartyId,
      payloadHash,
      aliasId: context.aliasId,
      contextIds: context.appId ? [context.appId] : [],
      anomalies: [],
      timestamp: Date.now(),
      payloadSizeBytes,
    });
  }

  /**
   * Get payload protection statistics.
   */
  getStats(): PayloadProtectionStats {
    const byService = new Map<string, ServicePayloadStats>();

    for (const [serviceId, stats] of this.serviceStats) {
      byService.set(serviceId, {
        serviceId,
        requestCount: stats.sizeTracker.count,
        meanPayloadSize: stats.sizeTracker.mean,
        stdDevPayloadSize: ewmaStdDev(stats.sizeTracker),
        meanLatency: stats.latencyTracker.mean,
        stdDevLatency: ewmaStdDev(stats.latencyTracker),
        requestsPerMinute: stats.requestTimestamps.length,
        circuitState: stats.circuitState,
        certFingerprint: stats.certFingerprint,
      });
    }

    let circuitBreakersTripped = 0;
    for (const stats of this.serviceStats.values()) {
      if (stats.circuitState === 'open') circuitBreakersTripped++;
    }

    return {
      outboundSigned: this.outboundSigned,
      inboundVerified: this.inboundVerified,
      fieldsEncrypted: this.fieldsEncrypted,
      anomaliesDetected: this.anomaliesDetected,
      circuitBreakersTripped,
      byService,
    };
  }

  /**
   * Get audit log entries.
   */
  getAuditLog(limit = 100): PayloadAuditEntry[] {
    return this.auditLog.slice(-limit);
  }

  // ── Private helpers ─────────────────────────────────────

  private canonicalize(obj: unknown): string {
    if (obj === null || obj === undefined) return '';
    if (typeof obj !== 'object') return String(obj);
    if (Array.isArray(obj)) {
      return '[' + obj.map(item => this.canonicalize(item)).join(',') + ']';
    }
    const sorted = Object.keys(obj as Record<string, unknown>).sort();
    return (
      '{' +
      sorted
        .map(
          k =>
            JSON.stringify(k) +
            ':' +
            this.canonicalize((obj as Record<string, unknown>)[k])
        )
        .join(',') +
      '}'
    );
  }

  private deriveFieldKey(thirdPartyId: string, aliasId?: string): Buffer {
    const input = `${this.config.appSigningKey}|${thirdPartyId}|${aliasId ?? 'default'}`;
    return crypto.createHash('sha256').update(input).digest();
  }

  /**
   * Stable per-record AAD context: binds field ciphertext to the
   * third-party/alias record it belongs to, independent of field identity.
   */
  private buildAADContext(thirdPartyId: string, aliasId?: string): string {
    return `${thirdPartyId}|${aliasId ?? 'default'}`;
  }

  /**
   * Full AAD for a single field: record context + field path, so ciphertext
   * from one field (or one record) cannot be substituted for another's
   * without the auth tag failing to verify on decrypt.
   */
  private buildFieldAAD(aadContext: string, fieldPath: string): string {
    return `${aadContext}|${fieldPath}`;
  }

  private isSensitiveField(fieldName: string): boolean {
    return this.piiRegexes.some(re => re.test(fieldName));
  }

  private walkAndEncrypt(
    obj: Record<string, unknown>,
    prefix: string,
    key: Buffer,
    encryptedFields: Map<string, EncryptedFieldMeta>,
    aadContext: string
  ): void {
    for (const [fieldName, value] of Object.entries(obj)) {
      const path = prefix ? `${prefix}.${fieldName}` : fieldName;

      if (this.isSensitiveField(fieldName) && typeof value === 'string') {
        // Encrypt this field, binding AAD to record context + field path
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        cipher.setAAD(
          Buffer.from(this.buildFieldAAD(aadContext, path), 'utf8')
        );
        let encrypted = cipher.update(value, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const authTag = cipher.getAuthTag().toString('hex');

        obj[fieldName] = encrypted;
        encryptedFields.set(path, {
          fieldPath: path,
          algorithm: 'aes-256-gcm',
          iv: iv.toString('hex'),
          authTag,
        });
      } else if (value && typeof value === 'object' && !Array.isArray(value)) {
        this.walkAndEncrypt(
          value as Record<string, unknown>,
          path,
          key,
          encryptedFields,
          aadContext
        );
      }
    }
  }

  private getNestedValue(obj: Record<string, unknown>, path: string): unknown {
    const parts = path.split('.');
    let current: unknown = obj;
    for (const part of parts) {
      if (current && typeof current === 'object') {
        current = (current as Record<string, unknown>)[part];
      } else {
        return undefined;
      }
    }
    return current;
  }

  private setNestedValue(
    obj: Record<string, unknown>,
    path: string,
    value: unknown
  ): void {
    const parts = path.split('.');
    // fieldPath here comes from encryptedFields metadata that travelled
    // with an inbound (untrusted) third-party payload — a malicious
    // "__proto__"/"constructor"/"prototype" segment would otherwise reach
    // Object.prototype via the bracket assignment below. Fails closed,
    // matching decryptSensitiveFields' own fail-closed contract.
    if (parts.some(part => UNSAFE_PATH_SEGMENTS.has(part))) {
      throw new Error(
        `[PayloadProtection] Refusing to set nested value at unsafe path "${path}" — contains a prototype-polluting segment`
      );
    }
    let current: Record<string, unknown> = obj;
    for (let i = 0; i < parts.length - 1; i++) {
      if (!current[parts[i]] || typeof current[parts[i]] !== 'object') {
        current[parts[i]] = {};
      }
      current = current[parts[i]] as Record<string, unknown>;
    }
    current[parts[parts.length - 1]] = value;
  }

  private extractSchemaSignature(
    obj: Record<string, unknown>
  ): Record<string, string> {
    const schema: Record<string, string> = {};
    for (const [key, value] of Object.entries(obj)) {
      if (value === null) schema[key] = 'null';
      else if (Array.isArray(value)) schema[key] = 'array';
      else schema[key] = typeof value;
    }
    return schema;
  }

  private compareSchemas(
    baseline: Record<string, string>,
    current: Record<string, string>
  ): string[] {
    const drifts: string[] = [];
    // Check for removed fields
    for (const key of Object.keys(baseline)) {
      if (!(key in current)) {
        drifts.push(`removed:${key}`);
      } else if (baseline[key] !== current[key]) {
        drifts.push(`type_change:${key}(${baseline[key]}→${current[key]})`);
      }
    }
    // New fields are additive — not a drift issue
    return drifts;
  }

  private getOrCreateServiceStats(serviceId: string) {
    let stats = this.serviceStats.get(serviceId);
    if (!stats) {
      stats = {
        sizeTracker: { mean: 0, variance: 0, count: 0 },
        latencyTracker: { mean: 0, variance: 0, count: 0 },
        requestTimestamps: [],
        circuitState: 'closed',
        circuitOpenedAt: 0,
        anomalyCount: 0,
      };
      this.serviceStats.set(serviceId, stats);
    }
    return stats;
  }

  private recordAudit(entry: PayloadAuditEntry): void {
    this.auditLog.push(entry);
    if (this.auditLog.length > this.config.maxAuditEntries) {
      this.auditLog.splice(
        0,
        this.auditLog.length - this.config.maxAuditEntries
      );
    }
  }
}
