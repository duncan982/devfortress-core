package net.devfortress;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * TierGate, ported from {@code packages/devfortress-sdk/src/tier-gate.ts}.
 * Covers feature gating end-to-end: a tier resolved the way {@link
 * LicenseManager} resolves it from the platform, fed into a {@link
 * TierGate}, correctly blocks a tier-ineligible feature.
 */
class TierGateTest {
    @Test
    void starterTierCanObserveButNotBlock() {
        TierGate gate = new TierGate(TierGate.SubscriptionTier.STARTER);
        assertTrue(gate.hasFeature(TierGate.Feature.CAN_OBSERVE));
        assertFalse(gate.canBlock());

        String error = gate.validateBlockAction("block_ip");
        assertNotNull(error, "Starter must not be allowed to block");
        assertTrue(error.contains("not available"));
    }

    @Test
    void proTierIsExternalClOnlyAndRejectsInternalHybrid() {
        TierGate gate = new TierGate(TierGate.SubscriptionTier.PRO);
        assertTrue(gate.canBlock());

        // Package A: Pro never gets internal/hybrid, even as a fallback request.
        assertEquals(TierGate.CLMode.EXTERNAL, gate.getEffectiveMode(TierGate.CLMode.INTERNAL));
        assertEquals(TierGate.CLMode.EXTERNAL, gate.getEffectiveMode(TierGate.CLMode.HYBRID));

        String error = gate.validateMode(TierGate.CLMode.INTERNAL);
        assertNotNull(error, "Pro is tier-ineligible for internal CL mode and must be blocked");
        assertTrue(error.contains("not available on the pro tier"));
    }

    @Test
    void teamTierDefaultsToHybridAndAllowsAllModes() {
        TierGate gate = new TierGate(TierGate.SubscriptionTier.TEAM);
        assertEquals(TierGate.CLMode.HYBRID, gate.getEffectiveMode(null));
        assertNull(gate.validateMode(TierGate.CLMode.INTERNAL));
        assertNull(gate.validateMode(TierGate.CLMode.HYBRID));
    }

    @Test
    void starterDailyEventLimitIsEnforced() {
        TierGate gate = new TierGate(TierGate.SubscriptionTier.STARTER);
        assertEquals(10_000, gate.getCapabilities().maxEventsPerDay());

        for (int i = 0; i < 10_000; i++) {
            gate.recordEvent();
        }
        TierGate.EventLimitResult result = gate.checkEventLimit();
        assertFalse(result.allowed(), "Starter must be blocked once its daily quota is exhausted");
        assertEquals(0, result.remaining());
    }

    @Test
    void enterpriseTierHasUnlimitedDailyEventsAndFullIclTier() {
        TierGate gate = new TierGate(TierGate.SubscriptionTier.ENTERPRISE);
        for (int i = 0; i < 50_000; i++) {
            gate.recordEvent();
        }
        assertTrue(gate.checkEventLimit().allowed());
        assertEquals(3, gate.getMaxICLTier());
        assertTrue(gate.isAirGapEnabled());
    }

    @Test
    void snapshotRoundTripPreservesCountersWithinTheSameDayAndMonth() {
        TierGate gate = new TierGate(TierGate.SubscriptionTier.PRO);
        gate.recordEvent();
        gate.recordEvent();
        gate.recordMonthlyEvent();

        TierGate.TierGateSnapshot snapshot = gate.toSnapshot();
        TierGate restored = TierGate.fromSnapshot(snapshot, false);

        assertEquals(TierGate.SubscriptionTier.PRO, restored.getTier());
        // Pro's daily limit is 100_000; 2 recorded events on each side must agree exactly.
        assertEquals(gate.checkEventLimit().remaining(), restored.checkEventLimit().remaining());
        assertEquals(100_000 - 2, restored.checkEventLimit().remaining());
    }

    /**
     * A tier resolved the way a host would resolve it from {@link LicenseManager}'s
     * wire-string tier, fed into {@link TierGate}, to demonstrate the two
     * modules' documented (string-value, not nominal-type) integration seam.
     */
    @Test
    void tierGateBuiltFromLicenseManagerWireTierBlocksTierIneligibleFeature() {
        LicenseManager.Tier licenseTier = LicenseManager.Tier.STARTER;
        TierGate gate = new TierGate(TierGate.SubscriptionTier.fromWire(licenseTier.wireValue()));

        assertFalse(gate.canBlock());
        assertNotNull(gate.validateBlockAction("block_ip"));
        assertFalse(gate.hasComplianceEvidence());
    }
}
