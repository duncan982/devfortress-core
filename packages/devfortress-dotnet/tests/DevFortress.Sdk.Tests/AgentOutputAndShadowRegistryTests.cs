using DevFortress;
using Xunit;

namespace DevFortress.Sdk.Tests;

/// <summary>
/// AgentOutputExfiltrationDetector (B7) and ShadowAgentRegistry (B10) — TODO 380, net-new public
/// modules (see AgentOutputExfiltrationDetector.cs and ShadowAgentRegistry.cs at the project
/// root). Like ConsentAndTrustChainTests.cs's coverage of B3/B4, this file's mere existence and
/// successful compilation from this separate test assembly is itself proof that both types are
/// public SDK surface, not internal/Tier2Gated.
/// </summary>
public class AgentOutputAndShadowRegistryTests
{
    [Fact]
    public void AgentOutputExfiltrationDetector_DetectsPrivateKeyAsBlockedCredentialLeak()
    {
        var detector = new AgentOutputExfiltrationDetector();
        var output = new AgentOutput(
            AgentId: "agent-1",
            OutputContent: "here is a key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
            OutputType: AgentOutputType.Text,
            DestinationType: OutputDestinationType.User,
            Timestamp: 1000);

        var result = detector.Analyze(output);

        Assert.True(result.Detected);
        Assert.Equal(ExfiltrationThreatType.CredentialLeak, result.ThreatType);
        Assert.Equal(ExfiltrationRecommendation.Block, result.Recommendation);
        Assert.NotNull(result.RedactedOutput);
        Assert.DoesNotContain("BEGIN RSA PRIVATE KEY", result.RedactedOutput);
    }

    [Fact]
    public void AgentOutputExfiltrationDetector_CleanOutput_IsAllowed()
    {
        var detector = new AgentOutputExfiltrationDetector();
        var output = new AgentOutput("agent-1", "The weather today is sunny with a high of 72F.",
            AgentOutputType.Text, OutputDestinationType.User, 1000);

        var result = detector.Analyze(output);

        Assert.False(result.Detected);
        Assert.Equal(ExfiltrationThreatType.None, result.ThreatType);
        Assert.Equal(ExfiltrationRecommendation.Allow, result.Recommendation);
    }

    [Fact]
    public void AgentOutputExfiltrationDetector_OversizedOutput_IsWarned()
    {
        var detector = new AgentOutputExfiltrationDetector(new ExfiltrationDetectorConfig(MaxOutputSizeBytes: 10));
        var output = new AgentOutput("agent-1", "this content is definitely longer than ten bytes",
            AgentOutputType.Text, OutputDestinationType.Api, 1000);

        var result = detector.Analyze(output);

        Assert.True(result.Detected);
        Assert.Equal(ExfiltrationThreatType.OversizedOutput, result.ThreatType);
        Assert.Equal(ExfiltrationRecommendation.Warn, result.Recommendation);
    }

    [Fact]
    public void ShadowAgentRegistry_RegisteredAgentIsNeverFlaggedAsShadow()
    {
        var registry = new ShadowAgentRegistry();
        registry.Register(new NewAgentRegistration("agent-42", "Billing Bot", "team-x", ["read:invoices"]));

        var detection = registry.Detect("agent-42", ["automated request pattern"]);

        Assert.False(detection.Detected);
        Assert.Equal(ShadowAgentRecommendation.Monitor, detection.Recommendation);
        Assert.Equal(1, registry.GetStats().RegisteredCount);
    }

    [Fact]
    public void ShadowAgentRegistry_UnregisteredBotLikeIndicators_AreDetectedAsShadow()
    {
        var registry = new ShadowAgentRegistry(new ShadowAgentConfig(AutoBlock: true));

        var detection = registry.Detect("unknown-fingerprint",
        [
            "automated request pattern seen in logs",
            "consistent timing between requests observed",
            "sequential resource enumeration detected",
        ]);

        Assert.True(detection.Detected);
        Assert.True(detection.Confidence > 0.7);
        Assert.Equal(ShadowAgentRecommendation.Block, detection.Recommendation);
        Assert.Equal(1, registry.GetStats().ShadowDetections);
        Assert.Equal(1, registry.GetStats().BlockedShadows);
    }

    [Fact]
    public void ShadowAgentRegistry_PruneInactive_DeactivatesStaleAgents()
    {
        // A negative timeout pushes the prune cutoff strictly after "now", guaranteeing it's
        // past any timestamp taken moments earlier — avoids a millisecond-rounding flake.
        var registry = new ShadowAgentRegistry(new ShadowAgentConfig(HeartbeatTimeoutMs: -1000));
        registry.Register(new NewAgentRegistration("agent-7", "Stale Bot", "team-y", []));

        var pruned = registry.PruneInactive();

        Assert.Contains("agent-7", pruned);
        Assert.Equal(0, registry.GetStats().ActiveCount);
    }
}
