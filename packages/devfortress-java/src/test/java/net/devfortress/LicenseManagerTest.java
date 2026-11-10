package net.devfortress;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * LicenseManager (CV-M1/M4/M7), ported from
 * {@code packages/devfortress-sdk/src/license-manager.ts}. Covers the TODO
 * 321 bug class this class exists to fix on the client side: a license
 * check that fails must never degrade silently — it must be visibly logged
 * and, past the grace period, flip into an observable degraded state.
 */
class LicenseManagerTest {
    private record LogCall(String level, String message) {
    }

    private static final class CapturingLogger implements Logger {
        final List<LogCall> calls = new ArrayList<>();

        @Override
        public void log(String level, String message, Map<String, Object> fields) {
            calls.add(new LogCall(level, message));
        }
    }

    @Test
    void successfulLicenseCheckResolvesTierAndModelVersion() {
        RecordingTransport transport = new RecordingTransport()
                .respond(200, "{\"tier\":\"enterprise\",\"modelVersion\":\"v2026.1\"}");
        CapturingLogger logger = new CapturingLogger();

        try (LicenseManager license = LicenseManager.builder("test-key", "https://platform.example")
                .transport(transport).logger(logger).build()) {
            LicenseManager.LicenseState state = license.checkLicense();

            assertTrue(state.valid());
            assertEquals(LicenseManager.Tier.ENTERPRISE, state.tier());
            assertFalse(state.degraded());
            assertEquals(0, state.consecutiveFailures());
            assertEquals(1, transport.callCount());
            assertEquals("https://platform.example/api/sdk/license-check", transport.calls.get(0).url());

            // CV-M4: a successful check with a modelVersion syncs the ML model as fresh.
            LicenseManager.ModelState model = license.getModelState();
            assertEquals("v2026.1", model.modelVersion());
            assertFalse(model.expired());

            assertTrue(logger.calls.stream().anyMatch(c -> c.message().contains("License validated")));
        }
    }

    @Test
    void licenseCheckFailureDegradesGracefullyAndLogsVisiblyRatherThanFailingSilently() {
        RecordingTransport transport = new RecordingTransport().fail(new IOException("platform unreachable"));
        CapturingLogger logger = new CapturingLogger();

        // Zero grace period so one failure degrades immediately and deterministically.
        try (LicenseManager license = LicenseManager.builder("test-key", "https://platform.example")
                .transport(transport).logger(logger).gracePeriodMs(0).build()) {
            LicenseManager.LicenseState state = license.checkLicense();

            assertFalse(state.valid());
            assertTrue(state.degraded(), "SDK must degrade to monitor-only, not silently keep claiming a valid license");
            assertEquals(1, state.consecutiveFailures());
            assertNotNull(state.degradationReason());
            assertTrue(state.degradationReason().contains("platform unreachable"));

            // The exact bug class TODO 321 fixed: a failed check must be visible, never silent.
            assertTrue(logger.calls.stream().anyMatch(c -> "warn".equals(c.level()) && c.message().contains("degraded")));
            assertTrue(license.isDegraded());
            assertFalse(license.canPerformAction(LicenseManager.Action.BLOCK));
            assertTrue(license.canPerformAction(LicenseManager.Action.OBSERVE), "observe is always allowed, even degraded");
        }
    }

    @Test
    void rejectedLicenseIsNeverRetriedAsTransientAndFallsBackToStarter() {
        RecordingTransport transport = new RecordingTransport().respond(402, "{\"error\":\"payment_required\"}");
        try (LicenseManager license = LicenseManager.builder("test-key", "https://platform.example")
                .transport(transport).build()) {
            LicenseManager.LicenseState state = license.checkLicense();
            assertFalse(state.valid());
            assertTrue(state.degraded());
            assertEquals(LicenseManager.Tier.STARTER, state.tier());
            assertTrue(state.degradationReason().contains("402"));
        }
    }

    @Test
    void integrityHashIsStableForSameSecretAndKeyButChangesWithEitherInput() {
        LicenseManager a = LicenseManager.builder("key-a", "https://platform.example").integritySecret("secret-1").build();
        LicenseManager b = LicenseManager.builder("key-a", "https://platform.example").integritySecret("secret-1").build();
        LicenseManager c = LicenseManager.builder("key-b", "https://platform.example").integritySecret("secret-1").build();

        assertEquals(a.computeIntegrityHash(), b.computeIntegrityHash());
        assertFalse(a.computeIntegrityHash().equals(c.computeIntegrityHash()));

        LicenseManager.IntegrityResult verified = a.verifyIntegrity(b.computeIntegrityHash());
        assertFalse(verified.tampered());
        LicenseManager.IntegrityResult tampered = a.verifyIntegrity(c.computeIntegrityHash());
        assertTrue(tampered.tampered());
    }
}
