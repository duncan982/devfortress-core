using System.Text.Json;
using DevFortress;
using Xunit;

namespace DevFortress.Sdk.Tests;

/// <summary>
/// LicenseManager (CV-M1/M4/M7), TelemetryManager + TelemetryRollupBuffer (CV-M2 /
/// Anomaly-Gated Metering), and TierGate — TODO 369/370. All three are new public SDK surface
/// (see LicenseManager.cs, TelemetryManager.cs, TierGate.cs at the project root), ported from
/// the Node SDK's license-manager.ts, telemetry.ts, telemetry-rollup-buffer.ts and tier-gate.ts.
/// </summary>
public class LicenseTelemetryTierGateTests
{
    private sealed class RecordingLogger : IDevFortressLogger
    {
        public readonly List<(string Level, string Message)> Entries = [];
        public void Log(string level, string message, IReadOnlyDictionary<string, object?> fields) =>
            Entries.Add((level, message));
    }

    // ── LicenseManager ──────────────────────────────────────────

    [Fact]
    public async Task LicenseManager_SuccessfulCheck_ResolvesTierAndSyncsModel()
    {
        var transport = new RecordingTransport().Respond(200, "{\"tier\":\"team\",\"modelVersion\":\"v42\"}");
        using var manager = new LicenseManager("test-key", "https://example.test", transport: transport);

        var state = await manager.CheckLicenseAsync();

        Assert.True(state.Valid);
        Assert.Equal("team", state.Tier);
        Assert.False(state.Degraded);
        Assert.Equal(0, state.ConsecutiveFailures);
        Assert.True(manager.CanPerformAction(LicenseAction.Block));

        var model = manager.GetModelState();
        Assert.Equal("v42", model.ModelVersion);
        Assert.False(model.Expired);

        // The request must have been signed, and the API key must never go on the wire.
        var call = transport.Calls.Single();
        Assert.Contains("/api/sdk/license-check", call.Url);
        Assert.True(call.Headers.ContainsKey(Signer.SignatureHeader));
        Assert.DoesNotContain("test-key", System.Text.Encoding.UTF8.GetString(call.Body));
    }

    [Fact]
    public async Task LicenseManager_CheckFailure_DegradesVisiblyNotSilently()
    {
        // gracePeriodMs=0 so the very first failure immediately crosses the grace boundary —
        // this is the exact TODO 321 bug class: a 404/5xx must never leave the SDK silently
        // stuck in monitor-only mode. It must both flip Degraded AND log a visible warning.
        var transport = new RecordingTransport().Respond(500, "{}");
        var logger = new RecordingLogger();
        using var manager = new LicenseManager("test-key", "https://example.test", gracePeriodMs: 0,
            transport: transport, logger: logger);

        var state = await manager.CheckLicenseAsync();

        Assert.False(state.Valid); // never successfully validated
        Assert.True(state.Degraded);
        Assert.NotNull(state.DegradationReason);
        Assert.True(manager.IsDegraded());
        Assert.False(manager.CanPerformAction(LicenseAction.Block));
        Assert.False(manager.CanPerformAction(LicenseAction.RateLimit));
        Assert.True(manager.CanPerformAction(LicenseAction.Observe)); // observe is always allowed, even degraded

        // The failure must be visible via the logger — never silent.
        Assert.Contains(logger.Entries, e => e.Level == "warn" && e.Message.Contains("degraded to monitor-only"));
    }

    [Fact]
    public async Task LicenseManager_RejectedLicense_DegradesImmediatelyOn402Or403()
    {
        var transport = new RecordingTransport().Respond(402, "{}");
        var logger = new RecordingLogger();
        using var manager = new LicenseManager("test-key", "https://example.test", transport: transport, logger: logger);

        var state = await manager.CheckLicenseAsync();

        Assert.False(state.Valid);
        Assert.True(state.Degraded);
        Assert.Equal("starter", state.Tier);
        Assert.Contains(logger.Entries, e => e.Level == "warn" && e.Message.Contains("License rejected"));
    }

    [Fact]
    public void LicenseManager_IntegrityHash_IsStableAndDetectsTampering()
    {
        using var manager = new LicenseManager("test-key", "https://example.test", integritySecret: "shh");

        var verify1 = manager.VerifyIntegrity();
        Assert.False(verify1.Tampered);

        var verify2 = manager.VerifyIntegrity("not-the-real-hash");
        Assert.True(verify2.Tampered);
        Assert.Equal(verify1.Hash, verify2.Hash); // same inputs, deterministic hash
    }

    // ── TelemetryManager ────────────────────────────────────────

    [Fact]
    public async Task TelemetryManager_HeartbeatSendsSignedSnapshotAndResetsCounters()
    {
        var transport = new RecordingTransport().Respond(200, "{}");
        using var telemetry = new TelemetryManager("test-key", "https://example.test", transport: transport);

        telemetry.RecordEvent();
        telemetry.RecordEvent();
        telemetry.RecordBlock();
        telemetry.RecordLatency(42);

        await telemetry.SendHeartbeatAsync();

        var call = transport.Calls.Single();
        Assert.Contains("/api/sdk/heartbeat", call.Url);
        Assert.True(call.Headers.ContainsKey(Signer.SignatureHeader));

        using var doc = JsonDocument.Parse(call.Body);
        Assert.Equal(2, doc.RootElement.GetProperty("eventCount").GetInt64());
        Assert.Equal(1, doc.RootElement.GetProperty("blockCount").GetInt64());

        var state = telemetry.GetState();
        Assert.Equal(0, state.EventCount); // reset after a send attempt
        Assert.Equal(0, state.BlockCount);
    }

    [Fact]
    public async Task TelemetryRollupBuffer_AggregatesByAliasOrIpAndHourThenFlushes()
    {
        var transport = new RecordingTransport().Respond(200, "{}");
        using var buffer = new TelemetryRollupBuffer("test-key", "https://example.test/api/events", transport: transport);

        buffer.Add(new RollupContributionInput("1.2.3.4", "/a", IsError: false, LatencyMs: 10));
        buffer.Add(new RollupContributionInput("1.2.3.4", "/b", IsError: true, LatencyMs: 20));
        buffer.Add(new RollupContributionInput("5.6.7.8", "/a", IsError: false, LatencyMs: 5));

        await buffer.FlushAsync();

        var call = transport.Calls.Single();
        Assert.EndsWith("/telemetry-rollup", call.Url);

        using var doc = JsonDocument.Parse(call.Body);
        var contributions = doc.RootElement.GetProperty("contributions").EnumerateArray().ToList();
        Assert.Equal(2, contributions.Count); // one bucket per distinct (aliasOrIpKey, hour)

        var aliasBucket = contributions.Single(c => c.GetProperty("aliasOrIpKey").GetString() == "1.2.3.4");
        Assert.Equal(2, aliasBucket.GetProperty("requestCount").GetInt64());
        Assert.Equal(2, aliasBucket.GetProperty("uniqueEndpointsInBatch").GetInt32());
        Assert.Equal(1, aliasBucket.GetProperty("errorCount").GetInt64());
        Assert.Equal(30, aliasBucket.GetProperty("latencySumMs").GetDouble());
    }

    [Fact]
    public void TelemetryRollupBuffer_HourlyPeriodKey_IsThirteenCharUtcHourBucket()
    {
        var instant = new DateTimeOffset(2026, 8, 27, 14, 59, 59, TimeSpan.Zero);
        Assert.Equal("2026-08-27T14", TelemetryRollupBuffer.HourlyPeriodKey(instant));
    }

    // ── TierGate ────────────────────────────────────────────────

    [Theory]
    [InlineData(SubscriptionTier.Starter, false)]
    [InlineData(SubscriptionTier.Pro, true)]
    [InlineData(SubscriptionTier.Team, true)]
    [InlineData(SubscriptionTier.Enterprise, true)]
    public void TierGate_CanBlock_MatchesCapabilityMatrix(SubscriptionTier tier, bool expected)
    {
        var gate = new TierGate(tier);
        Assert.Equal(expected, gate.CanBlock());
    }

    [Fact]
    public void TierGate_BlocksTierIneligibleFeature_HybridOnStarter()
    {
        var gate = new TierGate(SubscriptionTier.Starter);

        var modeError = gate.ValidateMode(CLMode.Hybrid);
        Assert.NotNull(modeError);
        Assert.Contains("not available on the starter tier", modeError);
        Assert.Equal(CLMode.External, gate.GetEffectiveMode(CLMode.Hybrid)); // falls back to the tier default

        var blockError = gate.ValidateBlockAction("block_ip");
        Assert.NotNull(blockError);
        Assert.Contains("Blocking is not available", blockError);
        Assert.False(gate.HasFeature(nameof(TierCapabilities.CanBlock)));
    }

    [Fact]
    public void TierGate_MonthlyQuota_TracksUsageAndBlocksOverLimit()
    {
        var gate = new TierGate(SubscriptionTier.Starter); // 50_000/month
        for (int i = 0; i < 3; i++) gate.RecordMonthlyEvent();

        var usage = gate.GetMonthlyUsage();
        Assert.Equal(3, usage.Used);
        Assert.Equal(50_000, usage.Limit);

        var quota = gate.CheckMonthlyQuota();
        Assert.True(quota.Allowed);
        Assert.Equal(49_997.0, quota.Remaining);
    }

    [Fact]
    public void TierGate_SnapshotRoundTrip_PreservesCountersWithinSameResetWindow()
    {
        var gate = new TierGate(SubscriptionTier.Pro, hybridAddonEnabled: true);
        gate.RecordEvent();
        gate.RecordMonthlyEvent();
        var snapshot = gate.ToSnapshot();

        var restored = TierGate.FromSnapshot(snapshot);

        Assert.Equal(SubscriptionTier.Pro, restored.GetTier());
        Assert.Equal(99_999.0, restored.CheckEventLimit().Remaining); // 100_000 - the 1 already recorded
        Assert.Equal(1, restored.GetMonthlyUsage().Used);
    }

    [Fact]
    public void TierGate_UnlimitedTier_ReportsInfiniteRemaining()
    {
        var gate = new TierGate(SubscriptionTier.Enterprise); // MaxEventsPerDay == 0 (unlimited)
        var limit = gate.CheckEventLimit();
        Assert.True(limit.Allowed);
        Assert.True(double.IsPositiveInfinity(limit.Remaining));
    }
}
