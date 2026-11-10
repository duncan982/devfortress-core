package net.devfortress;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * AgentOutputExfiltrationDetector (B7) and ShadowAgentRegistry (B10), new
 * public SDK surface (net-net ports — Java previously had neither pillar at
 * all) — see src/main/java/net/devfortress/AgentOutputExfiltrationDetector.java
 * and src/main/java/net/devfortress/ShadowAgentRegistry.java. Same shape as
 * {@link ConsentAndTrustChainTest} (B3/B4): behavioral coverage proving both
 * classes are public, constructible, and functionally correct from outside
 * their own file.
 */
class ExfiltrationDetectorAndShadowRegistryTest {
    @Test
    void exfiltrationDetectorFlagsAwsKeyAsCredentialLeakAndRedactsIt() {
        AgentOutputExfiltrationDetector detector = new AgentOutputExfiltrationDetector();
        AgentOutputExfiltrationDetector.AgentOutput output = new AgentOutputExfiltrationDetector.AgentOutput(
                "agent-1", "Here is the key: AKIAABCDEFGHIJKLMNOP for the deploy job",
                AgentOutputExfiltrationDetector.OutputType.TEXT,
                AgentOutputExfiltrationDetector.DestinationType.USER, System.currentTimeMillis());

        AgentOutputExfiltrationDetector.ExfiltrationResult result = detector.analyze(output);

        assertTrue(result.detected());
        assertEquals(AgentOutputExfiltrationDetector.ThreatType.CREDENTIAL_LEAK, result.threatType());
        assertEquals(AgentOutputExfiltrationDetector.Recommendation.BLOCK, result.recommendation());
        assertTrue(result.redactedOutput().contains("[REDACTED]"));
        assertFalse(result.redactedOutput().contains("AKIAABCDEFGHIJKLMNOP"));
    }

    @Test
    void exfiltrationDetectorAllowsCleanOutput() {
        AgentOutputExfiltrationDetector detector = new AgentOutputExfiltrationDetector();
        AgentOutputExfiltrationDetector.AgentOutput output = new AgentOutputExfiltrationDetector.AgentOutput(
                "agent-1", "The weather today is sunny with a high of 72F.",
                AgentOutputExfiltrationDetector.OutputType.TEXT,
                AgentOutputExfiltrationDetector.DestinationType.USER, System.currentTimeMillis());

        AgentOutputExfiltrationDetector.ExfiltrationResult result = detector.analyze(output);

        assertFalse(result.detected());
        assertEquals(AgentOutputExfiltrationDetector.ThreatType.NONE, result.threatType());
        assertEquals(AgentOutputExfiltrationDetector.Recommendation.ALLOW, result.recommendation());
    }

    @Test
    void exfiltrationDetectorFlagsOversizedOutput() {
        AgentOutputExfiltrationDetector detector = AgentOutputExfiltrationDetector.builder()
                .maxOutputSizeBytes(10).build();
        AgentOutputExfiltrationDetector.AgentOutput output = new AgentOutputExfiltrationDetector.AgentOutput(
                "agent-1", "this output content is far longer than ten bytes",
                AgentOutputExfiltrationDetector.OutputType.TEXT,
                AgentOutputExfiltrationDetector.DestinationType.API, System.currentTimeMillis());

        AgentOutputExfiltrationDetector.ExfiltrationResult result = detector.analyze(output);

        assertTrue(result.detected());
        assertEquals(AgentOutputExfiltrationDetector.ThreatType.OVERSIZED_OUTPUT, result.threatType());
    }

    @Test
    void shadowAgentRegistryFlagsUnregisteredAutomatedTrafficAsShadow() {
        ShadowAgentRegistry registry = ShadowAgentRegistry.builder().autoBlock(true).build();

        ShadowAgentRegistry.ShadowAgentDetection detection = registry.detect("unknown-fingerprint-1", List.of(
                "automated request pattern (>500 req/min observed)",
                "consistent timing between requests seen in logs",
                "sequential resource enumeration across /users/1 .. /users/9000"));

        assertTrue(detection.detected());
        assertTrue(detection.confidence() > 0.7);
        assertEquals(ShadowAgentRegistry.Recommendation.BLOCK, detection.recommendation());
        assertEquals(1, registry.getStats().shadowDetections());
        assertEquals(1, registry.getStats().blockedShadows());
    }

    @Test
    void shadowAgentRegistryDoesNotFlagARegisteredActiveAgent() {
        ShadowAgentRegistry registry = new ShadowAgentRegistry();
        ShadowAgentRegistry.RegisteredAgent registered = registry.register(
                new ShadowAgentRegistry.AgentRegistration("agent-42", "billing-bot", "team-finance", List.of("read:invoices")));

        assertTrue(registered.active);

        ShadowAgentRegistry.ShadowAgentDetection detection = registry.detect("agent-42", List.of(
                "automated request pattern (>500 req/min observed)"));

        assertFalse(detection.detected(), "a registered, active agent must never be flagged as a shadow");
        assertEquals(1, registry.getStats().registeredCount());
        assertEquals(1, registry.getStats().activeCount());
    }

    @Test
    void shadowAgentRegistryPrunesAgentsThatMissedHeartbeatTimeout() throws InterruptedException {
        ShadowAgentRegistry registry = ShadowAgentRegistry.builder().heartbeatTimeoutMs(1).build();
        registry.register(new ShadowAgentRegistry.AgentRegistration("agent-stale", "stale-bot", "team-x", List.of()));

        Thread.sleep(5);
        List<String> pruned = registry.pruneInactive();

        assertTrue(pruned.contains("agent-stale"));
        assertEquals(0, registry.getStats().activeCount());
    }
}
