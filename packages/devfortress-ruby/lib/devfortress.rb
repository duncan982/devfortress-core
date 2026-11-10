# frozen_string_literal: true

require_relative "devfortress/version"
require_relative "devfortress/signer"
require_relative "devfortress/client_ip"
require_relative "devfortress/classifier"
require_relative "devfortress/delivery_result"
require_relative "devfortress/transport"
require_relative "devfortress/client"
require_relative "devfortress/webhook_verification"
require_relative "devfortress/webhook_verifier"
require_relative "devfortress/observer"

# Tier 2 (public pillars only — see lib/devfortress/internal.rb, not
# required here, for the gated surface).
require_relative "devfortress/credential_vault"
require_relative "devfortress/credential_isolation"
require_relative "devfortress/agent_adapter"
require_relative "devfortress/agent_security"
require_relative "devfortress/api_key_aliasing"
require_relative "devfortress/alias_verify"
require_relative "devfortress/tool_call_sequence_validator"
require_relative "devfortress/agent_loop_detector"
require_relative "devfortress/prompt_injection_filter"
require_relative "devfortress/response_webhook_client"

# Filing 4 (B7/B10) — public, disclosure-comment only (see PATENT-GATE
# comments in each file), matching the Node SDK's posture. B3/B4 are
# gated as of TODO 420 (2026-11-03) — see lib/devfortress/internal.rb.
require_relative "devfortress/agent_output_exfiltration_detector"
require_relative "devfortress/shadow_agent_registry"

# License/telemetry/tier-gating (CV-M1/M2/M4/M7, CV-S2-S6) — client-side
# port of the platform license-check/heartbeat fix (TODO 321) and the
# Node SDK's tier enforcement. Mirrors license-manager.ts, telemetry.ts,
# telemetry-rollup-buffer.ts and tier-gate.ts.
require_relative "devfortress/license_manager"
require_relative "devfortress/telemetry"
require_relative "devfortress/tier_gate"

# Graduated rate limiting (Invention A3, TODO 373) + platform circuit
# breaking / bounded map (TODO 372). Mirrors graduated-rate-limiter.ts,
# circuit-breaker.ts, and internal-closed-loop-engine.ts's BoundedMap.
require_relative "devfortress/graduated_rate_limiter"
require_relative "devfortress/circuit_breaker"
require_relative "devfortress/bounded_map"

# Internal Closed-Loop Protection Engine (TODO 407 port) — internal/hybrid
# CL mode's 3-tier decision engine. Mirrors internal-closed-loop-engine.ts.
require_relative "devfortress/internal_closed_loop_engine"

# Cold-start behavioral baselines (Invention A1, TODO 374) + LSH
# fingerprint clustering / campaign detection (Invention A2, TODO 374).
# Mirrors cold-start-detector.ts and lsh-cluster-engine.ts.
#
# Conditional (2026-11-08 standalone-build audit, round 2, Part 3): neither
# class is referenced anywhere else in this gem (confirmed — grepped client.rb/
# observer.rb/every other lib file before making this conditional), so unlike
# the Node SDK's cold-start-detector.ts/lsh-cluster-engine.ts (hard-wired into
# DevFortressCore's own observe() path, requiring a behavioral stub — see
# open-core-strip.sh Op 14), a bare require boundary is sufficient here: on
# the open-core checkout these two files are proprietary and stripped, and
# DevFortress::ColdStartDetector / DevFortress::LSHClusterEngine simply don't
# exist — no other code path depends on them existing. In the private repo
# both files are always present, so this rescue branch never fires there.
begin
  require_relative "devfortress/cold_start_detector"
  require_relative "devfortress/lsh_cluster_engine"
rescue LoadError
  nil
end

# Clock drift anomaly detection (Invention A18, TODO 419/422).
# Mirrors security-extensions.ts's ClockDriftDetector.
require_relative "devfortress/clock_drift_detector"

# Unified audit trail (CL-M3, TODO 371) -- in-memory only, not
# tamper-evident; see unified_audit_trail.rb's own comment. AbuseIPDB
# threat-intel enrichment (TODO 375). Mirrors unified-audit.ts and
# abuseipdb.ts.
require_relative "devfortress/unified_audit_trail"
# Conditional (2026-11-08 standalone-build audit, round 2, Part 3): the
# AbuseIPDB trade-secret integration is proprietary and stripped from the
# open-core checkout. Not referenced anywhere else in this gem (same check
# as cold_start_detector/lsh_cluster_engine above), so a bare require
# boundary is sufficient — DevFortress::AbuseIPDB simply doesn't exist on
# that checkout. Never fires in the private repo, where the file always
# exists.
begin
  require_relative "devfortress/abuseipdb"
rescue LoadError
  nil
end

module DevFortress
end
