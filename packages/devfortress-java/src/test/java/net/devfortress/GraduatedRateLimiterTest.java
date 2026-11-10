package net.devfortress;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;

/**
 * GraduatedRateLimiter (Invention A3, TODO 373), ported from
 * {@code packages/devfortress-sdk/src/graduated-rate-limiter.ts}.
 */
class GraduatedRateLimiterTest {

    @SuppressWarnings("unchecked")
    private static Map<String, Object> entriesOf(GraduatedRateLimiter limiter) {
        try {
            Field f = GraduatedRateLimiter.class.getDeclaredField("entries");
            f.setAccessible(true);
            return (Map<String, Object>) f.get(limiter);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }

    private static void forceCooldownElapsed(GraduatedRateLimiter limiter, String key) {
        try {
            Object entry = entriesOf(limiter).get(key);
            Field cooldownField = entry.getClass().getDeclaredField("cooldownUntil");
            cooldownField.setAccessible(true);
            cooldownField.setLong(entry, System.currentTimeMillis() - 10);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }

    private static void clearTimestamps(GraduatedRateLimiter limiter, String key) {
        try {
            Object entry = entriesOf(limiter).get(key);
            Field timestampsField = entry.getClass().getDeclaredField("timestamps");
            timestampsField.setAccessible(true);
            ((java.util.List<?>) timestampsField.get(entry)).clear();
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void observationStageBelowHalfLimit() {
        GraduatedRateLimiter limiter = new GraduatedRateLimiter(GraduatedRateLimiter.Config.defaults());
        GraduatedRateLimiter.RateLimitResult result = limiter.check("alias-1");
        assertEquals(GraduatedRateLimiter.RateLimitStage.OBSERVATION, result.stage());
        assertFalse(result.blocked());
        limiter.destroy();
    }

    @Test
    void warningStageAtHalfLimit() {
        GraduatedRateLimiter limiter = new GraduatedRateLimiter(
                GraduatedRateLimiter.Config.defaults().withDefaultLimit(10));
        GraduatedRateLimiter.RateLimitResult result = null;
        for (int i = 0; i < 5; i++) {
            result = limiter.check("alias-1");
        }
        assertEquals(GraduatedRateLimiter.RateLimitStage.WARNING, result.stage());
        assertFalse(result.blocked());
        limiter.destroy();
    }

    @Test
    void softLimitInjectsLatencyWithJitter() {
        GraduatedRateLimiter limiter = new GraduatedRateLimiter(
                GraduatedRateLimiter.Config.defaults().withDefaultLimit(10).withSoftLimitBaseLatencyMs(2000));
        GraduatedRateLimiter.RateLimitResult result = null;
        for (int i = 0; i < 8; i++) {
            result = limiter.check("alias-1");
        }
        assertEquals(GraduatedRateLimiter.RateLimitStage.SOFT_LIMIT, result.stage());
        assertFalse(result.blocked());
        assertTrue(result.injectedLatencyMs() > 0);
        limiter.destroy();
    }

    @Test
    void hardBlockAtLimit() {
        GraduatedRateLimiter limiter = new GraduatedRateLimiter(
                GraduatedRateLimiter.Config.defaults().withDefaultLimit(5));
        GraduatedRateLimiter.RateLimitResult result = null;
        for (int i = 0; i < 5; i++) {
            result = limiter.check("alias-1");
        }
        assertEquals(GraduatedRateLimiter.RateLimitStage.HARD_BLOCK, result.stage());
        assertTrue(result.blocked());
        assertEquals(60, result.cooldownSeconds());
        limiter.destroy();
    }

    @Test
    void escalatingCooldownDoublesEachConsecutiveBlock() {
        GraduatedRateLimiter limiter = new GraduatedRateLimiter(
                GraduatedRateLimiter.Config.defaults().withDefaultLimit(1).withInitialCooldownSeconds(60));

        GraduatedRateLimiter.RateLimitResult first = limiter.check("alias-1");
        assertEquals(GraduatedRateLimiter.RateLimitStage.HARD_BLOCK, first.stage());
        assertEquals(60, first.cooldownSeconds());

        forceCooldownElapsed(limiter, "alias-1");
        clearTimestamps(limiter, "alias-1");

        GraduatedRateLimiter.RateLimitResult second = limiter.check("alias-1");
        assertEquals(GraduatedRateLimiter.RateLimitStage.HARD_BLOCK, second.stage());
        assertEquals(120, second.cooldownSeconds());
        limiter.destroy();
    }

    @Test
    void revokesAfterMaxConsecutiveBlocks() {
        GraduatedRateLimiter limiter = new GraduatedRateLimiter(
                GraduatedRateLimiter.Config.defaults().withDefaultLimit(1).withMaxConsecutiveBlocks(3));

        for (int i = 0; i < 3; i++) {
            limiter.check("alias-1");
            forceCooldownElapsed(limiter, "alias-1");
        }

        GraduatedRateLimiter.RateLimitResult result = limiter.check("alias-1");
        assertEquals(GraduatedRateLimiter.RateLimitStage.REVOCATION, result.stage());
        assertTrue(limiter.isRevoked("alias-1"));
        limiter.destroy();
    }

    @Test
    void revokedAliasStaysBlockedWithoutReRevoking() {
        GraduatedRateLimiter limiter = new GraduatedRateLimiter(GraduatedRateLimiter.Config.defaults());
        limiter.revokeAlias("alias-1");
        GraduatedRateLimiter.RateLimitResult result = limiter.check("alias-1");
        assertEquals(GraduatedRateLimiter.RateLimitStage.REVOCATION, result.stage());
        assertFalse(result.revoke());
        limiter.destroy();
    }

    @Test
    void resetAliasClearsEscalation() {
        GraduatedRateLimiter limiter = new GraduatedRateLimiter(
                GraduatedRateLimiter.Config.defaults().withDefaultLimit(1));

        limiter.check("alias-1");
        forceCooldownElapsed(limiter, "alias-1");
        clearTimestamps(limiter, "alias-1");
        GraduatedRateLimiter.RateLimitResult escalated = limiter.check("alias-1");
        assertEquals(120, escalated.cooldownSeconds());

        limiter.resetAlias("alias-1");

        GraduatedRateLimiter.RateLimitResult result = limiter.check("alias-1");
        assertEquals(60, result.cooldownSeconds());
        limiter.destroy();
    }

    @Test
    void perEndpointLimitsOverrideDefault() {
        GraduatedRateLimiter limiter = new GraduatedRateLimiter(
                GraduatedRateLimiter.Config.defaults().withDefaultLimit(100)
                        .withEndpointLimits(Map.of("/api/auth/*", 2)));
        limiter.check("alias-1", "/api/auth/login");
        GraduatedRateLimiter.RateLimitResult result = limiter.check("alias-1", "/api/auth/login");
        assertEquals(2, result.limit());
        assertEquals(GraduatedRateLimiter.RateLimitStage.HARD_BLOCK, result.stage());
        limiter.destroy();
    }

    @Test
    void burstDetectionTriggersHardBlock() {
        GraduatedRateLimiter limiter = new GraduatedRateLimiter(
                GraduatedRateLimiter.Config.defaults().withDefaultLimit(1000).withBurstLimit(3));
        GraduatedRateLimiter.RateLimitResult result = null;
        for (int i = 0; i < 4; i++) {
            result = limiter.check("alias-1");
        }
        assertTrue(result.burstDetected());
        assertEquals(GraduatedRateLimiter.RateLimitStage.HARD_BLOCK, result.stage());
        limiter.destroy();
    }

    @Test
    void maxEntriesEvictsOldestAlias() {
        GraduatedRateLimiter limiter = new GraduatedRateLimiter(
                GraduatedRateLimiter.Config.defaults().withDefaultLimit(100).withMaxEntries(2));
        limiter.check("alias-1");
        limiter.check("alias-2");
        limiter.check("alias-3");

        assertEquals(2, limiter.size());
        assertFalse(entriesOf(limiter).containsKey("alias-1"));
        limiter.destroy();
    }
}
