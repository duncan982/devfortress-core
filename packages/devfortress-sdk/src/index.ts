/**
 * DevFortress SDK v4.8.0 — Main Entry Point (Node.js)
 *
 * For browser usage, import from '@devfortress/sdk/browser' instead.
 * For zero-config quick start, import from '@devfortress/sdk/quick'.
 * For Express middleware, use devfortressMiddleware from this package.
 * For FastAPI/Flask, see the Python middleware in src/middleware/
 *
 * NEW in v4.3 — Mandatory observability fields:
 * - method, path, severity, clMode, authPhase, actionTaken, responseLatencyMs
 *   are now required on LiveThreatEvent for all SDK event submissions
 *
 * v4.0 — Closed-Loop Mode Architecture:
 * - Three protection modes: external, internal, hybrid
 * - Circuit breaker with automatic failover (hybrid mode)
 * - Unified audit trail (internal + external merged timeline)
 * - Tier-gated feature access (Starter/Pro/Enterprise)
 * - Backward compatible — existing external-mode code works unchanged
 *
 * v3.3:
 * - Internal Closed-Loop Engine (3-tier deterministic + ML + async relay)
 * - Air-gap mode support (no external dependencies in Tier 1 + 2)
 *
 * v3.2:
 * - Agent security (AgentAdapter, credential management, anomaly detection)
 *
 * v3.1:
 * - Zero-config quick start (df.init({ apiKey }))
 * - Privacy-strict mode, Debug mode
 *
 * v3.0:
 * - DevFortress class with observe(), isBlocked(), onThreatDetected()
 * - AbuseIPDB integration, Credential isolation security, Webhook handler
 *
 * @packageDocumentation
 */

// v3.1 — Zero-config quick start
export { init, getInstance, getDataSnapshot } from './quick';
export type { QuickConfig } from './quick';

// v3.0 — Primary export
// see './internal' (devfortress-sdk/internal), excluded from the npm tarball.
export {
  DevFortressCore as DevFortress,
  DevFortressCore as DevFortressSDK,
} from './devfortress';

// v4.0 — Closed-Loop Mode Architecture
export { PlatformCircuitBreaker } from './circuit-breaker';
export type { CircuitState, CircuitBreakerConfig } from './circuit-breaker';

// v4.4 — Shared utilities
export { BoundedMap } from './internal-closed-loop-engine';

export { UnifiedAuditTrail } from './unified-audit';
export type {
  AuditSource,
  UnifiedAuditEntry,
  UnifiedAuditConfig,
} from './unified-audit';

export { TierGate } from './tier-gate';
export type {
  SubscriptionTier,
  TierCapabilities,
  TierGateSnapshot,
} from './tier-gate';

// v4.4 — Revenue Protection (CV-M / CV-S)
export { LicenseManager } from './license-manager';
export type {
  LicenseState,
  ModelState,
  LicenseManagerConfig,
} from './license-manager';

export { TelemetryManager } from './telemetry';
export type { TelemetrySnapshot, TelemetryConfig } from './telemetry';
export {
  TelemetryRollupBuffer,
  hourlyPeriodKey,
} from './telemetry-rollup-buffer';
export type {
  RollupContributionInput,
  TelemetryRollupBufferConfig,
} from './telemetry-rollup-buffer';

// v3.0 — AbuseIPDB integration
export {
  checkIP,
  reportIP,
  syncBlacklist,
  scoreThreat,
  getCachedScore,
  getAbuseIPDBRateLimitStatus,
} from './abuseipdb';

// v3.0 — Credential isolation security
export {
  CredentialIsolationManager,
  ThreatInterceptor,
} from './credential-isolation';
export type {
  CacheAdapter,
  CredentialIsolationManagerConfig,
  RevocationReason,
} from './credential-isolation';

// v3.2 — Agent Security (IP-C1 through IP-C5)
export { AgentAdapter, validateAgentId } from './agent';
export type { AgentToolCall, AgentAdapterConfig } from './agent';
export {
  AgentCredentialManager,
  AgentBaselineEngine,
  AgentAnomalyDetector,
  AgentScopeEnforcer,
} from './agent-security';
export type {
  AgentCredentialType,
  AgentCredentialAliasData,
  AgentExecutionContext,
  AgentBaselineMetrics,
  AgentSessionRecord,
  AgentAnomalyType,
  AgentAnomalySignal,
  AgentScopeDefinition,
} from './agent-security';

// v3.3 — Internal Closed-Loop Engine & Air-Gap Mode
export {
  InternalClosedLoopEngine,
  matchesKnownAttackPattern,
} from './internal-closed-loop-engine';
export type {
  InternalCLConfig,
  InternalCLRequest,
  InternalCLResult,
  InternalCLDecision,
  InternalCLAction,
  InternalCLAuditEntry,
  InternalCLRule,
} from './internal-closed-loop-engine';

export { DevFortressAirGap } from './air-gap';
export type { AirGapConfig } from './air-gap';

// v4.5 — Webhook Nonce Registry (replay prevention)
export { WebhookNonceRegistry } from './webhook-nonce-registry';
export type {
  NonceRegistryConfig,
  NonceRegistryMetrics,
  NonceValidationResult,
} from './webhook-nonce-registry';

// v4.5 — Graduated Rate Limiter
export { GraduatedRateLimiter } from './graduated-rate-limiter';
export type {
  GraduatedRateLimiterConfig,
  RateLimitStage,
  RateLimitResult,
} from './graduated-rate-limiter';

// C35 - DevOps & CI/CD Pipeline Security
export { PipelineSecurityModule } from './devops/pipeline-security';
export type {
  PipelineSecurityOptions,
  WebhookValidationOptions,
} from './devops/pipeline-security';

// v4.6 — ML Threat Classifier (Embedded ONNX + Platform fallback)
export { MLClassifier, extractFeatures } from './ml-classifier';
export type {
  EventFeatures,
  ClassificationResult,
  MLClassifierConfig,
} from './ml-classifier';

// v4.7 — Password Spray Detector (cross-account failed-auth correlation)
export { PasswordSprayDetector } from './password-spray-detector';
export type {
  PasswordSprayConfig,
  SprayDetectionResult,
  AuthFailureEvent,
} from './password-spray-detector';

// v4.7 — Sensitive Action Monitor (behavioral deviation scoring)
export { SensitiveActionMonitor } from './sensitive-action-monitor';
export type {
  SensitiveActionConfig,
  SensitiveActionType,
  SensitiveActionEvent,
  SensitiveActionResult,
} from './sensitive-action-monitor';

// v4.7 — Registration Pattern Detector (mass registration campaign detection)
export { RegistrationPatternDetector } from './registration-pattern-detector';
export type {
  RegistrationDetectorConfig,
  RegistrationEvent,
  RegistrationResult,
} from './registration-pattern-detector';

// v4.7 — Config Integrity Verifier (runtime SDK config tamper detection)
export { ConfigIntegrityVerifier } from './config-integrity-verifier';
export type {
  ConfigIntegrityConfig,
  ConfigViolation,
  ConfigIntegrityResult,
} from './config-integrity-verifier';

// v4.7 — OAuth Redirect Validator
export { OAuthRedirectValidator } from './security-extensions';
export type {
  OAuthRedirectConfig,
  RedirectValidationResult,
} from './security-extensions';

// v4.7 — MFA Fatigue Detector
export { MFAFatigueDetector } from './security-extensions';
export type { MFAFatigueConfig, MFAFatigueResult } from './security-extensions';

// v4.7 — Session Fixation Guard
export { SessionFixationGuard } from './security-extensions';
export type {
  SessionFixationConfig,
  SessionFingerprint,
  SessionValidationResult,
} from './security-extensions';

// v4.7 — Business Logic Abuse Profiler
export { BusinessLogicProfiler } from './security-extensions';
export type {
  BusinessLogicConfig,
  BusinessLogicResult,
} from './security-extensions';

// v4.7 — Refresh Token Binding Enforcer
export { RefreshTokenBindingEnforcer } from './security-extensions';
export type {
  TokenBindingConfig,
  TokenBindingResult,
} from './security-extensions';

// v4.7 — Indirect Prompt Injection Filter
export {
  PromptInjectionFilter,
  PromptInjectionFilter as IndirectPromptInjectionFilter,
} from './security-extensions';
export type {
  PromptInjectionConfig,
  PromptInjectionResult,
} from './security-extensions';

// v4.7 — Agent Feedback Poisoning Guard
export { FeedbackPoisoningGuard } from './security-extensions';
export type {
  FeedbackPoisoningConfig,
  FeedbackEvent,
  FeedbackAnalysisResult,
} from './security-extensions';

// v4.7 — Clock Drift Anomaly Detector
export { ClockDriftDetector } from './security-extensions';
export type { ClockDriftConfig, ClockDriftResult } from './security-extensions';

export { APIKeyAliasingService } from './api-key-aliasing';
export type {
  AliasWorkload,
  AliasState,
  AliasConfig,
  AliasRecord,
  AliasAuditEvent,
  AliasCreationResult,
  AliasRotationResult,
  AliasValidationResult,
  AliasStats,
} from './api-key-aliasing';

export { signedPlatformRequest } from './http-client';
export type { SignedRequestOptions } from './http-client';
export { SDK_VERSION } from './version';

export { PayloadProtectionService } from './payload-protection';
export type {
  PayloadDirection,
  PayloadProtectionConfig,
  SigningContext,
  PayloadAttestation,
  FieldEncryptionResult,
  EncryptedFieldMeta,
  ResponseVerificationResult,
  PayloadAnomaly,
  PayloadAuditEntry,
  PayloadProtectionStats,
  ServicePayloadStats,
} from './payload-protection';

// (see src/internal.ts) — excluded from the published npm tarball pending
// patent filing outcome (see packages/devfortress-sdk/package.json).

// v4.7 — Cold-Start Detector (population baselines + adaptive EWMA)
export { ColdStartDetector } from './cold-start-detector';
export type {
  ColdStartConfig,
  BehavioralFeatureVector,
  BaselineQuality,
  ColdStartDetectionResult,
} from './cold-start-detector';

// v4.7 — LSH Cluster Engine (fingerprint similarity + campaign detection)
export { LSHClusterEngine } from './lsh-cluster-engine';
export type {
  LSHClusterConfig,
  RequestFingerprint,
  FingerprintCluster,
  CampaignSignature,
  LSHMatchResult,
} from './lsh-cluster-engine';

// v4.8 — Tool-Call Sequence Validator (prompt injection detection)
export { ToolCallSequenceValidator } from './tool-call-sequence-validator';
export type {
  ToolCallGraph,
  ToolCallGraphNode,
  ToolCallSequenceConfig,
  ToolCallValidationResult,
} from './tool-call-sequence-validator';

// v4.8 — Agent Loop Detector (runaway agent circuit breaker)
export { AgentLoopDetector } from './agent-loop-detector';
export type {
  AgentLoopConfig,
  LoopCycleContext,
  LoopDetectionResult,
} from './agent-loop-detector';

// v4.8 — Validation-friendly aliases (align script names → class names)
export { RefreshTokenBindingEnforcer as RefreshTokenBinding } from './security-extensions';

// ── Platform Intelligence ──────────────────────────────────────────────────
// Patent Pending — KIPI KE/P/2026/005973
// Prior art: https://www.tdcommons.org/dpubs_series/9908/

/**
 * CrossCustomerThreatIntel
 * Patent Pending — KIPI KE/P/2026/005973
 * Prior art: https://www.tdcommons.org/dpubs_series/9908/
 */
// v4.9 — Cross-Customer Threat Intelligence
export { CrossCustomerThreatIntel } from './cross-customer-threat-intel';
export type {
  CrossCustomerConfig,
  ThreatSignal,
  CrossCustomerResult,
  CrossCustomerStats,
} from './cross-customer-threat-intel';

// v4.10 — Agent Output Exfiltration Detector
export { AgentOutputExfiltrationDetector } from './agent-output-exfiltration-detector';
export type {
  ExfiltrationDetectorConfig,
  AgentOutput,
  ExfiltrationResult,
} from './agent-output-exfiltration-detector';

// v4.10 — Shadow Agent Registry
export { ShadowAgentRegistry } from './shadow-agent-registry';
export type {
  ShadowAgentConfig,
  RegisteredAgent,
  ShadowAgentDetection,
  AgentRegistryStats,
} from './shadow-agent-registry';

// ── end Platform Intelligence ── //
//
// ConsentAliasLifecycle (B3), MultiHopTrustChain (B4), IDORDetector (B5),
// SupplyChainValidator (B6), TLSCertPinningEnforcer (B8),
// EnumerationTimingShield (B9), DNSHijackingDetector (B11), and
// PredictiveAttackTrajectory (B12) remain in internal.ts — see that file's
// header comment for why. Do not re-add exports for these eight here.
//
// The M-Pesa Webhook Protection module (v4.9 — S36) also moved to
// internal.ts, not for patent-boundary reasons but because it's
// Kenya-specific logic that must not ship in the public npm package — see
// DF-Kenya-Specific-Audit-Report-13-11-26.md. Do not re-add mpesa exports
// here; use the internal entry point instead.

// v4.9 — S38: Low-Bandwidth Transport (2G/3G optimized)
export {
  compressPayload,
  decompressPayload,
  shouldBatch,
  buildMinimalPayload,
  estimatePayloadBytes,
} from './transport/low-bandwidth';
export type {
  ConnectionType,
  LowBandwidthConfig,
} from './transport/low-bandwidth';
export { OfflineQueue } from './transport/offline-queue';

// v5.0 — SDK Specialization Mode Architecture
export * from './specialization/manifest';
export * from './specialization/plugin-interface';
export * from './specialization/mode-composer';
export * from './specialization/entitlement-matrix';

// v1.x — Backward compatible exports
export { DevFortressClient } from './client';
export { verifyAliasBinding, AliasVerifyError } from './alias-verify';
export type {
  AliasOperationClass,
  AliasVerifyContext,
  AliasVerifyOptions,
  AliasVerifyResult,
  AliasBindingViolation,
} from './alias-verify';
export { devfortressMiddleware } from './middleware/express';

// Types
export type {
  // v4.0 types
  CLMode,
  // v3.0 types
  DevFortressConfig,
  EnrichmentConfig,
  ObserveResult,
  ObserveOptions,
  ThreatEvent,
  ThreatSeverity,
  ThreatHandler,
  ActionReport,
  WebhookPayload,
  AbuseIPDBScore,
  AbuseIPDBCheckResult,
  CompositeScoreResult,
  IsolatedCredentialData,
  // v1.x backward compatible types
  DevFortressClientOptions,
  LiveThreatEvent,
  EventType,
  SeverityLevel,
  DevFortressMiddlewareOptions,
  ApiResponse,
  SecurityArm,
} from './types';

// devfortress-sdk/internal (see src/internal.ts) — excluded from the
// published npm tarball pending patent filing outcome (see
// packages/devfortress-sdk/package.json).
export * from './resilience/cl-limitations';
export * from './agent/llm-protection';
export * from './agent/mcp-protection';
export * from './web3/web3-protection';
export * from './supply-chain/supply-chain-watch';
export * from './agent/advanced-agent-security';
export * from './agent/dual-llm';
export * from './agent/trajectory-validation';
export * from './agent/semantic-input-filter';
export * from './ecommerce/fraud-prevention';
export * from './fintech/transaction-monitoring';
export * from './healthcare/access-control';
export * from './saas/tenant-isolation';
export * from './apm/security-context';
export * from './uba/behavior-analytics';
export * from './auth/jit-permissions';
export * from './agent/agentic-soc';
