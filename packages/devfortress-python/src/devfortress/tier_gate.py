"""DevFortress SDK — Tier Gating & Feature Access Control.

Port of the Node SDK's ``tier-gate.ts``.

Enforces feature access based on subscription tier:

  Starter:    Observe events; response is webhook-dispatched and
              self-executed by the customer (no platform-side blocking).
  Pro:        View + block via external CL only — no internal/hybrid,
              not even as an add-on (Package A, 2026-08-28).
  Team:       External, internal, and hybrid all available as first-class
              capabilities (default: hybrid) — the entry point for
              internal/hybrid CL under Package A.
  Enterprise: Can select internal, external, or hybrid (default: hybrid
              with internal backup, external primary).

``TierGate`` depends on ``LicenseManager`` to resolve the active tier —
callers construct a ``TierGate`` with whatever tier ``LicenseManager``
last confirmed.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Dict, List, Literal, Optional

from .license_manager import SubscriptionTier

CLMode = Literal["external", "internal", "hybrid"]
ICLTier = Literal[0, 1, 2, 3]

__all__ = [
    "SubscriptionTier",
    "CLMode",
    "TierCapabilities",
    "TierGateSnapshot",
    "TierGate",
]


# ── Tier Definitions ────────────────────────────────────────


@dataclass
class TierCapabilities:
    """Full feature-access profile for one subscription tier."""

    can_observe: bool
    """Can observe/collect events."""
    can_block: bool
    """Can execute blocking actions."""
    allowed_modes: List[CLMode]
    """Allowed closed-loop modes."""
    default_mode: CLMode
    """Default mode for this tier."""
    hybrid_is_addon: bool
    """Whether hybrid is an add-on (requires extra payment)."""
    internal_as_backup_only: bool
    """Internal CL acts as backup only (legacy Pro behavior)."""
    can_configure_rules: bool
    """Can configure custom rules."""
    can_access_audit: bool
    """Can access audit trail."""
    can_manage_webhooks: bool
    """Can manage webhook secrets."""
    max_events_per_day: int
    """Maximum events per day (0 = unlimited)."""
    max_blocked_ips: int
    """Maximum blocked IPs (0 = unlimited)."""
    # ── CV-S2: Tiered ICL Capabilities ──
    icl_max_tier: ICLTier
    """ICL tiers available: 0=none, 1=deterministic, 2=ML, 3=full."""
    air_gap_enabled: bool
    """Whether air-gap (offline) mode is available."""
    custom_rules_enabled: bool
    """Whether custom ICL rules are available."""
    # ── CV-S3: Monthly Event Quotas ──
    max_events_per_month: int
    """Maximum events per month (0 = unlimited)."""
    # ── CV-S4: Alert Channels ──
    platform_alerts: bool
    """Platform alert channels (email/Slack/PagerDuty) available."""
    # ── CV-S5: Shared State ──
    shared_state: bool
    """Cross-instance shared state (IP blocklists, baselines) via platform."""
    # ── CV-S6: Compliance Evidence ──
    compliance_evidence: bool
    """Compliance evidence generation (PDF reports, audit exports)."""


# ── Tier Capability Matrix ──────────────────────────────────

_TIER_CAPABILITIES: Dict[SubscriptionTier, TierCapabilities] = {
    "starter": TierCapabilities(
        can_observe=True,
        can_block=False,
        allowed_modes=["external"],
        default_mode="external",
        hybrid_is_addon=False,
        internal_as_backup_only=False,
        can_configure_rules=False,
        can_access_audit=False,
        can_manage_webhooks=False,
        max_events_per_day=10_000,
        max_blocked_ips=0,
        # CV-S2: Starter gets Tier 1 deterministic rules only
        icl_max_tier=1,
        air_gap_enabled=False,
        custom_rules_enabled=False,
        # CV-S3: 50K events/month (matches SUBSCRIPTION_PRICING, Option B pricing)
        max_events_per_month=50_000,
        # CV-S4: No platform alerts
        platform_alerts=False,
        # CV-S5: No shared state
        shared_state=False,
        # CV-S6: No compliance evidence
        compliance_evidence=False,
    ),
    "pro": TierCapabilities(
        can_observe=True,
        can_block=True,
        # Package A (2026-08-28): Pro gets External CL only, at no point in
        # time does it get ICL/hybrid — differentiation comes from
        # platform-executed response, post-auth detection, alias isolation,
        # and AI insights, never from CL mode depth. Internal/Hybrid access
        # starts at Team.
        allowed_modes=["external"],
        default_mode="external",
        hybrid_is_addon=False,
        internal_as_backup_only=False,
        can_configure_rules=False,
        can_access_audit=True,
        can_manage_webhooks=True,
        max_events_per_day=100_000,
        max_blocked_ips=1_000,
        # CV-S2: Pro has no ICL access — External CL only (Package A)
        icl_max_tier=0,
        air_gap_enabled=False,
        custom_rules_enabled=False,
        # CV-S3: 75K events/month (matches SUBSCRIPTION_PRICING, Option B pricing)
        max_events_per_month=75_000,
        # CV-S4: Platform alerts enabled
        platform_alerts=True,
        # CV-S5: Shared state enabled
        shared_state=True,
        # CV-S6: No compliance evidence (Enterprise only)
        compliance_evidence=False,
    ),
    "team": TierCapabilities(
        can_observe=True,
        can_block=True,
        # Package A (2026-08-28): Team is the new entry point for
        # Internal/Hybrid CL — takes on the internal/hybrid capability
        # profile Pro used to have, but as a first-class capability (no
        # add-on gate, no backup-only limit).
        allowed_modes=["external", "internal", "hybrid"],
        default_mode="hybrid",
        hybrid_is_addon=False,
        internal_as_backup_only=False,
        can_configure_rules=False,
        can_access_audit=True,
        can_manage_webhooks=True,
        max_events_per_day=0,  # Unlimited (ingestion rate; monthly billing quota below still caps flagged events)
        max_blocked_ips=5_000,
        # CV-S2: Team gets Tier 1 + Tier 2 ML (same ceiling Pro used to have)
        icl_max_tier=2,
        air_gap_enabled=False,
        custom_rules_enabled=False,
        # CV-S3: 100K events/month (matches SUBSCRIPTION_PRICING, Option B pricing)
        max_events_per_month=100_000,
        # CV-S4: Platform alerts enabled
        platform_alerts=True,
        # CV-S5: Shared state enabled
        shared_state=True,
        # CV-S6: Compliance evidence generation (matches Team's advertised compliance PDF reports)
        compliance_evidence=True,
    ),
    "enterprise": TierCapabilities(
        can_observe=True,
        can_block=True,
        allowed_modes=["external", "internal", "hybrid"],
        default_mode="hybrid",
        hybrid_is_addon=False,
        internal_as_backup_only=False,
        can_configure_rules=True,
        can_access_audit=True,
        can_manage_webhooks=True,
        max_events_per_day=0,  # Unlimited
        max_blocked_ips=0,  # Unlimited
        # CV-S2: Enterprise gets all tiers + air-gap + custom rules
        icl_max_tier=3,
        air_gap_enabled=True,
        custom_rules_enabled=True,
        # CV-S3: Unlimited events/month
        max_events_per_month=0,
        # CV-S4: Full alert channels
        platform_alerts=True,
        # CV-S5: Full shared state
        shared_state=True,
        # CV-S6: Compliance evidence generation
        compliance_evidence=True,
    ),
}


def _day_start(moment: datetime) -> float:
    return moment.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()


def _month_start(moment: datetime) -> float:
    return moment.replace(day=1, hour=0, minute=0, second=0, microsecond=0).timestamp()


# ── Tier Gate Enforcer ──────────────────────────────────────


@dataclass
class TierGateSnapshot:
    """S15: Serializable snapshot of TierGate mutable state."""

    tier: SubscriptionTier
    hybrid_addon_enabled: bool
    daily_event_count: int
    daily_reset_time: float
    monthly_event_count: int
    monthly_reset_time: float
    snapshot_timestamp: float


class TierGate:
    def __init__(self, tier: SubscriptionTier, *, hybrid_addon_enabled: bool = False):
        self.tier = tier
        # Per-instance copy — the matrix entry is a shared module-level
        # singleton and must never be mutated in place (mirrors Node's
        # `{ ...TIER_CAPABILITIES[tier] }` shallow copy).
        self.capabilities = replace(_TIER_CAPABILITIES[tier])
        self.hybrid_addon_enabled = hybrid_addon_enabled
        self._daily_event_count = 0
        self._daily_reset_time = _day_start(datetime.now())
        self._monthly_event_count = 0
        self._monthly_reset_time = _month_start(datetime.now())

    def get_effective_mode(self, requested_mode: Optional[CLMode] = None) -> CLMode:
        """Get the effective closed-loop mode for this tier.

        Validates the requested mode against tier permissions.
        """
        if not requested_mode:
            return self.capabilities.default_mode

        if requested_mode not in self.capabilities.allowed_modes:
            return self.capabilities.default_mode

        # Pro tier: hybrid requires add-on
        if (
            self.tier == "pro"
            and requested_mode == "hybrid"
            and self.capabilities.hybrid_is_addon
            and not self.hybrid_addon_enabled
        ):
            return "external"

        return requested_mode

    def can_block(self) -> bool:
        """Check if blocking is allowed for this tier."""
        return self.capabilities.can_block

    def check_event_limit(self) -> dict:
        """Check if the daily event limit has been reached.
        Returns ``{"allowed": bool, "remaining": float}``.
        """
        day_start = _day_start(datetime.now())
        if self._daily_reset_time < day_start:
            self._daily_event_count = 0
            self._daily_reset_time = day_start

        if self.capabilities.max_events_per_day == 0:
            return {"allowed": True, "remaining": math.inf}

        remaining = self.capabilities.max_events_per_day - self._daily_event_count
        return {"allowed": remaining > 0, "remaining": max(0, remaining)}

    def record_event(self) -> None:
        """Record an event (for limit tracking)."""
        self._daily_event_count += 1

    def has_feature(self, feature: str) -> bool:
        """Check if a specific capability field is "available" for this tier.

        Mirrors Node's loose ``hasFeature``: booleans pass through, numbers
        are "available" whether zero (unlimited) or positive, and lists are
        available when non-empty.
        """
        value = getattr(self.capabilities, feature, None)
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value > 0 or value == 0
        if isinstance(value, list):
            return len(value) > 0
        return False

    def get_capabilities(self) -> TierCapabilities:
        """Full capabilities for this tier."""
        return self.capabilities

    def get_tier(self) -> SubscriptionTier:
        """The current tier name."""
        return self.tier

    def validate_block_action(self, action: str) -> Optional[str]:
        """Validate a blocking action against tier permissions.
        Returns an error message if not allowed, or ``None`` if allowed.
        """
        if not self.capabilities.can_block:
            return (
                f"Blocking is not available on the {self.tier} tier. "
                "Upgrade to Pro or Enterprise to enable blocking."
            )

        if self.capabilities.max_blocked_ips > 0 and action == "block_ip":
            # Caller should check actual blocked count against this limit
            return None

        return None

    def validate_mode(self, mode: CLMode) -> Optional[str]:
        """Validate a mode selection against tier permissions.
        Returns an error message if not allowed, or ``None`` if allowed.
        """
        if mode not in self.capabilities.allowed_modes:
            allowed = ", ".join(self.capabilities.allowed_modes)
            return f"The '{mode}' mode is not available on the {self.tier} tier. Allowed modes: {allowed}."

        if (
            self.tier == "pro"
            and mode == "hybrid"
            and self.capabilities.hybrid_is_addon
            and not self.hybrid_addon_enabled
        ):
            return "Hybrid mode requires the hybrid add-on on the Pro tier. Enable it in your subscription settings."

        return None

    def _reset(self) -> None:
        """Reset daily/monthly counters (for testing)."""
        self._daily_event_count = 0
        self._daily_reset_time = 0
        self._monthly_event_count = 0
        self._monthly_reset_time = 0

    # ── CV-S2: Tiered ICL Capabilities ──────────────────────────

    def get_max_icl_tier(self) -> ICLTier:
        """Maximum ICL tier available for this subscription.
        0: no ICL (monitor-only). 1: deterministic rules only.
        2: Tier 1 + Tier 2 ML scoring. 3: all tiers + air-gap + custom rules.
        """
        return self.capabilities.icl_max_tier

    def is_icl_tier_available(self, tier: Literal[1, 2, 3]) -> bool:
        """Check if a specific ICL tier is available."""
        return self.capabilities.icl_max_tier >= tier

    def is_air_gap_enabled(self) -> bool:
        """Check if air-gap mode is available."""
        return self.capabilities.air_gap_enabled

    def can_configure_custom_rules(self) -> bool:
        """Check if custom ICL rules can be configured."""
        return self.capabilities.custom_rules_enabled

    # ── CV-S3: Monthly Event Quotas ──────────────────────────────

    def check_monthly_quota(self) -> dict:
        """Check monthly event quota.
        Returns ``{"allowed": bool, "remaining": float, "limit": int}``.
        """
        month_start = _month_start(datetime.now())
        if self._monthly_reset_time < month_start:
            self._monthly_event_count = 0
            self._monthly_reset_time = month_start

        limit = self.capabilities.max_events_per_month
        if limit == 0:
            return {"allowed": True, "remaining": math.inf, "limit": 0}

        remaining = limit - self._monthly_event_count
        return {"allowed": remaining > 0, "remaining": max(0, remaining), "limit": limit}

    def record_monthly_event(self) -> None:
        """Record an event against the monthly quota."""
        self._monthly_event_count += 1

    def get_monthly_usage(self) -> dict:
        """Monthly usage stats for the telemetry heartbeat."""
        limit = self.capabilities.max_events_per_month
        percent_used = round((self._monthly_event_count / limit) * 100) if limit > 0 else 0
        return {"used": self._monthly_event_count, "limit": limit, "percent_used": percent_used}

    # ── CV-S4/S5/S6: Platform Feature Checks ────────────────────

    def has_platform_alerts(self) -> bool:
        """CV-S4: ICL mode can only log to console/filesystem."""
        return self.capabilities.platform_alerts

    def has_shared_state(self) -> bool:
        """CV-S5: ICL maintains per-instance state only."""
        return self.capabilities.shared_state

    def has_compliance_evidence(self) -> bool:
        """CV-S6: ICL provides raw logs but no compliance formatting."""
        return self.capabilities.compliance_evidence

    # ── S15: Usage Metering Persistence ─────────────────────────

    def to_snapshot(self) -> TierGateSnapshot:
        """Snapshot mutable state for persistence across restarts.
        Caller should serialize and store in DB/file.
        """
        return TierGateSnapshot(
            tier=self.tier,
            hybrid_addon_enabled=self.hybrid_addon_enabled,
            daily_event_count=self._daily_event_count,
            daily_reset_time=self._daily_reset_time,
            monthly_event_count=self._monthly_event_count,
            monthly_reset_time=self._monthly_reset_time,
            snapshot_timestamp=datetime.now().timestamp(),
        )

    @staticmethod
    def from_snapshot(snapshot: TierGateSnapshot, *, hybrid_addon_enabled: bool = False) -> "TierGate":
        """Restore state from a previously saved snapshot.
        Ignores snapshot if the tier has changed or counters are stale
        (past their reset boundary).
        """
        gate = TierGate(snapshot.tier, hybrid_addon_enabled=snapshot.hybrid_addon_enabled)

        now = datetime.now()
        today_start = _day_start(now)
        month_start = _month_start(now)

        # Restore daily count only if snapshot is from today
        if snapshot.daily_reset_time >= today_start:
            gate._daily_event_count = snapshot.daily_event_count
            gate._daily_reset_time = snapshot.daily_reset_time

        # Restore monthly count only if snapshot is from this month
        if snapshot.monthly_reset_time >= month_start:
            gate._monthly_event_count = snapshot.monthly_event_count
            gate._monthly_reset_time = snapshot.monthly_reset_time

        return gate
