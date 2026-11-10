"""DevFortress Python SDK (external mode).

Event reporting is the original surface: ``DevFortressClient``, the
Flask/FastAPI middlewares, signing, and webhook verification.

Agent security (added in 0.3.0) ports the Node SDK's three core security
pillars — credential aliasing, agent-identity behavioral fingerprinting,
and closed-loop response. See each submodule's docstring for what it
ports and from where. Agent-security symbols are importable from their
submodules directly (``from devfortress.agent_security import
AgentBaselineEngine``, etc.) — this top-level ``__init__`` re-exports
only the event-reporting surface plus the small set of agent-security
entry points most demos need.
"""

from .agent import AgentAdapter, AgentToolCall, ObserveResult, validate_agent_id
from .agent_loop_detector import AgentLoopDetector, LoopDetectionResult
from .agent_output_exfiltration_detector import (
    AgentOutput,
    AgentOutputExfiltrationDetector,
    ExfiltrationResult,
)
from .agent_security import (
    AgentAnomalyDetector,
    AgentAnomalySignal,
    AgentBaselineEngine,
    AgentCredentialManager,
    AgentScopeEnforcer,
)
try:
    # AbuseIPDB trade-secret integration is proprietary and stripped from
    # the open-core checkout (2026-11-08 standalone-build audit, round 2).
    # Not imported by any other module in this package (confirmed by
    # grepping before adding this guard), so a plain ImportError guard is
    # enough — these names simply aren't bound on that checkout, same
    # pattern as the Node/Ruby SDKs' boundary for this module. Never
    # triggers in the private repo, where abuseipdb.py always exists.
    from .abuseipdb import (
        AbuseIPDBCheckResult,
        AbuseIPDBError,
        CompositeScoreResult,
        check_ip,
        get_abuseipdb_rate_limit_status,
        get_cached_score,
        report_ip,
        score_threat,
        sync_blacklist,
    )
except ImportError:
    pass
from .client import DevFortressClient, DevFortressError
from .clock_drift_detector import (
    ClockDriftAction,
    ClockDriftDetector,
    ClockDriftResult,
    ClockDriftSeverity,
    ClockDriftTrend,
)
from .closed_loop import ClosedLoopEngine, ThreatEvent
from .circuit_breaker import CircuitBreakerDiagnostics, PlatformCircuitBreaker
try:
    # Cold-start behavioral baseline detector (Invention A1) is proprietary
    # and stripped from the open-core checkout — same reasoning/guard as
    # the abuseipdb import above.
    from .cold_start_detector import (
        BaselineQuality,
        BehavioralFeatureVector,
        ColdStartDetectionResult,
        ColdStartDetector,
    )
except ImportError:
    pass
from .config_integrity_verifier import (
    ConfigIntegrityResult,
    ConfigIntegrityVerifier,
    ConfigViolation,
)
from .credential_isolation import CredentialIsolationManager, ThreatInterceptor
from .fastapi_middleware import DevFortressMiddleware
from .flask_middleware import DevFortressFlask
from .graduated_rate_limiter import GraduatedRateLimiter, RateLimitResult
from .internal_closed_loop_engine import (
    InternalCLAction,
    InternalCLAuditEntry,
    InternalCLConfig,
    InternalCLRequest,
    InternalCLResult,
    InternalCLRule,
    InternalClosedLoopEngine,
    matches_known_attack_pattern,
)
from .license_manager import LicenseManager, LicenseState, ModelState
try:
    # LSH fingerprint clustering / campaign detection (Invention A2) is
    # proprietary and stripped from the open-core checkout — same
    # reasoning/guard as the abuseipdb import above.
    from .lsh_cluster_engine import (
        CampaignSignature,
        ClusterInfo,
        LSHClusterEngine,
        LSHMatchResult,
        RequestFingerprint,
    )
except ImportError:
    pass
from .quick import get_instance, init
from .sensitive_action_monitor import (
    SensitiveActionEvent,
    SensitiveActionMonitor,
    SensitiveActionResult,
)
from .session_fixation_guard import (
    SessionFingerprint,
    SessionFixationGuard,
    SessionValidationResult,
)
from .shadow_agent_registry import (
    AgentRegistryStats,
    RegisteredAgent,
    ShadowAgentDetection,
    ShadowAgentRegistry,
)
from .signing import derive_key_id, sign_request, verify_request_signature
from .telemetry import (
    RollupContributionInput,
    TelemetryManager,
    TelemetryRollupBuffer,
    TelemetrySnapshot,
    hourly_period_key,
)
from .tier_gate import SubscriptionTier, TierCapabilities, TierGate, TierGateSnapshot
from .tool_call_sequence_validator import ToolCallSequenceValidator, ToolCallValidationResult
from .unified_audit_trail import UnifiedAuditEntry, UnifiedAuditTrail
from .webhook import WebhookVerification, verify_webhook_signature

__version__ = "0.3.0"

__all__ = [
    "DevFortressClient",
    "DevFortressError",
    "DevFortressMiddleware",
    "DevFortressFlask",
    "WebhookVerification",
    "verify_webhook_signature",
    "derive_key_id",
    "sign_request",
    "verify_request_signature",
    "init",
    "get_instance",
    # Credential aliasing
    "CredentialIsolationManager",
    "ThreatInterceptor",
    "AgentCredentialManager",
    # Behavioral fingerprinting
    "AgentAdapter",
    "AgentToolCall",
    "ObserveResult",
    "validate_agent_id",
    "AgentBaselineEngine",
    "AgentAnomalyDetector",
    "AgentAnomalySignal",
    "AgentScopeEnforcer",
    "ToolCallSequenceValidator",
    "ToolCallValidationResult",
    "AgentLoopDetector",
    "LoopDetectionResult",
    # Closed-loop response
    "ClosedLoopEngine",
    "ThreatEvent",
    # Internal/hybrid closed-loop mode (TODO 407 port)
    "InternalClosedLoopEngine",
    "InternalCLConfig",
    "InternalCLRequest",
    "InternalCLResult",
    "InternalCLAction",
    "InternalCLAuditEntry",
    "InternalCLRule",
    "matches_known_attack_pattern",
    # License / tier state (CV-M1, CV-M4, CV-M7)
    "LicenseManager",
    "LicenseState",
    "ModelState",
    # Telemetry heartbeat (CV-M2) + non-billing aggregate rollup buffer
    "TelemetryManager",
    "TelemetrySnapshot",
    "TelemetryRollupBuffer",
    "RollupContributionInput",
    "hourly_period_key",
    # Tier gating / feature access control
    "TierGate",
    "SubscriptionTier",
    "TierCapabilities",
    "TierGateSnapshot",
    # B7: Agent output exfiltration detection (moved from tier2_gated, TODO 380)
    "AgentOutputExfiltrationDetector",
    "AgentOutput",
    "ExfiltrationResult",
    # B10: Shadow agent registry (moved from tier2_gated, TODO 380)
    "ShadowAgentRegistry",
    "RegisteredAgent",
    "ShadowAgentDetection",
    "AgentRegistryStats",
    # Invention A3: graduated rate limiting (TODO 373)
    "GraduatedRateLimiter",
    "RateLimitResult",
    # Platform circuit breaker (TODO 372)
    "PlatformCircuitBreaker",
    "CircuitBreakerDiagnostics",
    # Invention A18: clock drift anomaly detection (TODO 419)
    "ClockDriftDetector",
    "ClockDriftResult",
    "ClockDriftTrend",
    "ClockDriftSeverity",
    "ClockDriftAction",
    # Invention A9: config integrity verification (TODO 419/426)
    "ConfigIntegrityVerifier",
    "ConfigIntegrityResult",
    "ConfigViolation",
    # Invention A13: session fixation guard (TODO 419/429)
    "SessionFixationGuard",
    "SessionFingerprint",
    "SessionValidationResult",
    # Invention A6: sensitive action monitor (TODO 419/424)
    "SensitiveActionMonitor",
    "SensitiveActionEvent",
    "SensitiveActionResult",
    # Invention A1: cold-start behavioral baselines (TODO 374)
    "ColdStartDetector",
    "BehavioralFeatureVector",
    "BaselineQuality",
    "ColdStartDetectionResult",
    # Invention A2: LSH fingerprint clustering / campaign detection (TODO 374)
    "LSHClusterEngine",
    "RequestFingerprint",
    "CampaignSignature",
    "LSHMatchResult",
    "ClusterInfo",
    # Unified audit trail (CL-M3, TODO 371) — in-memory only, not
    # tamper-evident; see unified_audit_trail.py's module docstring.
    "UnifiedAuditTrail",
    "UnifiedAuditEntry",
    # AbuseIPDB threat-intel enrichment (TODO 375)
    "check_ip",
    "report_ip",
    "sync_blacklist",
    "score_threat",
    "get_cached_score",
    "get_abuseipdb_rate_limit_status",
    "AbuseIPDBCheckResult",
    "CompositeScoreResult",
    "AbuseIPDBError",
]
