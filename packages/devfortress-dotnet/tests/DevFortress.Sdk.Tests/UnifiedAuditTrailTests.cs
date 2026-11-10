using DevFortress;
using Xunit;

namespace DevFortress.Sdk.Tests;

/// <summary>
/// UnifiedAuditTrail (CL-M3, TODO 371), ported from
/// <c>packages/devfortress-sdk/src/unified-audit.ts</c>.
/// </summary>
public class UnifiedAuditTrailTests
{
    private static int _seq;

    private static UnifiedAuditEntry MakeEntry(
        string? eventId = null,
        AuditSource source = AuditSource.Internal,
        string decision = "allow",
        double score = 10,
        double latencyMs = 0.5,
        string ip = "192.168.1.1",
        long? timestamp = null,
        string? userId = null,
        string? agentId = null,
        bool fallbackMode = false)
    {
        return new UnifiedAuditEntry(
            eventId ?? $"evt_{_seq++}",
            timestamp ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            source,
            1,
            decision,
            score,
            "low",
            latencyMs,
            ip,
            "/api/test",
            "GET",
            Array.Empty<string>(),
            userId,
            agentId,
            null,
            fallbackMode);
    }

    [Fact]
    public void RecordAndRetrieveEntries()
    {
        var audit = new UnifiedAuditTrail();
        audit.Record(MakeEntry(ip: "10.0.0.1"));
        audit.Record(MakeEntry(ip: "10.0.0.2"));
        Assert.Equal(2, audit.Query().Count);
    }

    [Fact]
    public void FilterBySource()
    {
        var audit = new UnifiedAuditTrail();
        audit.Record(MakeEntry(source: AuditSource.Internal));
        audit.Record(MakeEntry(source: AuditSource.External));
        audit.Record(MakeEntry(source: AuditSource.Hybrid));

        Assert.Single(audit.Query(new UnifiedAuditQuery(Source: AuditSource.Internal)));
        Assert.Single(audit.Query(new UnifiedAuditQuery(Source: AuditSource.External)));
        Assert.Single(audit.Query(new UnifiedAuditQuery(Source: AuditSource.Hybrid)));
    }

    [Fact]
    public void FilterByDecision()
    {
        var audit = new UnifiedAuditTrail();
        audit.Record(MakeEntry(decision: "allow"));
        audit.Record(MakeEntry(decision: "block"));
        audit.Record(MakeEntry(decision: "rate_limit"));

        Assert.Single(audit.Query(new UnifiedAuditQuery(Decision: "block")));
    }

    [Fact]
    public void FilterByMinScore()
    {
        var audit = new UnifiedAuditTrail();
        audit.Record(MakeEntry(score: 20));
        audit.Record(MakeEntry(score: 60));
        audit.Record(MakeEntry(score: 90));

        Assert.Equal(2, audit.Query(new UnifiedAuditQuery(MinScore: 50)).Count);
    }

    [Fact]
    public void FilterBySince()
    {
        var audit = new UnifiedAuditTrail();
        long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        audit.Record(MakeEntry(timestamp: now - 10_000));
        audit.Record(MakeEntry(timestamp: now - 5_000));
        audit.Record(MakeEntry(timestamp: now));

        Assert.Equal(2, audit.Query(new UnifiedAuditQuery(Since: now - 7_000)).Count);
    }

    [Fact]
    public void LimitResults()
    {
        var audit = new UnifiedAuditTrail();
        for (int i = 0; i < 50; i++)
        {
            audit.Record(MakeEntry());
        }
        Assert.Equal(10, audit.Query(new UnifiedAuditQuery(Limit: 10)).Count);
    }

    [Fact]
    public void CombineMultipleFilters()
    {
        var audit = new UnifiedAuditTrail();
        audit.Record(MakeEntry(source: AuditSource.Internal, decision: "block", score: 85));
        audit.Record(MakeEntry(source: AuditSource.Internal, decision: "allow", score: 10));
        audit.Record(MakeEntry(source: AuditSource.External, decision: "block", score: 90));

        var results = audit.Query(new UnifiedAuditQuery(Source: AuditSource.Internal, Decision: "block", MinScore: 80));
        Assert.Single(results);
        Assert.Equal(85, results[0].Score);
    }

    [Fact]
    public void StatsCountDecisionsBySource()
    {
        var audit = new UnifiedAuditTrail();
        audit.Record(MakeEntry(source: AuditSource.Internal));
        audit.Record(MakeEntry(source: AuditSource.Internal));
        audit.Record(MakeEntry(source: AuditSource.External));
        audit.Record(MakeEntry(source: AuditSource.Hybrid));

        var stats = audit.GetStats();
        Assert.Equal(4, stats.Total);
        Assert.Equal(2, stats.InternalDecisions);
        Assert.Equal(1, stats.ExternalDecisions);
        Assert.Equal(1, stats.HybridDecisions);
    }

    [Fact]
    public void StatsCountBlocksAllowsRateLimits()
    {
        var audit = new UnifiedAuditTrail();
        audit.Record(MakeEntry(decision: "block"));
        audit.Record(MakeEntry(decision: "allow"));
        audit.Record(MakeEntry(decision: "allow"));
        audit.Record(MakeEntry(decision: "rate_limit"));

        var stats = audit.GetStats();
        Assert.Equal(1, stats.TotalBlocks);
        Assert.Equal(2, stats.TotalAllows);
        Assert.Equal(1, stats.TotalRateLimits);
    }

    [Fact]
    public void AverageLatencies()
    {
        var audit = new UnifiedAuditTrail();
        audit.Record(MakeEntry(source: AuditSource.Internal, latencyMs: 0.5));
        audit.Record(MakeEntry(source: AuditSource.Internal, latencyMs: 1.5));
        audit.Record(MakeEntry(source: AuditSource.External, latencyMs: 100));
        audit.Record(MakeEntry(source: AuditSource.External, latencyMs: 200));

        var stats = audit.GetStats();
        Assert.Equal(1, stats.AvgInternalLatencyMs);
        Assert.Equal(150, stats.AvgExternalLatencyMs);
    }

    [Fact]
    public void DecisionDistribution()
    {
        var audit = new UnifiedAuditTrail();
        audit.Record(MakeEntry(source: AuditSource.Internal, decision: "allow"));
        audit.Record(MakeEntry(source: AuditSource.Internal, decision: "allow"));
        audit.Record(MakeEntry(source: AuditSource.Internal, decision: "block"));
        audit.Record(MakeEntry(source: AuditSource.External, decision: "allow"));

        var dist = audit.GetDecisionDistribution();
        Assert.Equal(2, dist["Internal:allow"]);
        Assert.Equal(1, dist["Internal:block"]);
        Assert.Equal(1, dist["External:allow"]);
    }

    [Fact]
    public void LatencyHistogramBucketsCorrectly()
    {
        var audit = new UnifiedAuditTrail();
        audit.Record(MakeEntry(latencyMs: 0.3));
        audit.Record(MakeEntry(latencyMs: 2));
        audit.Record(MakeEntry(latencyMs: 30));
        audit.Record(MakeEntry(latencyMs: 100));
        audit.Record(MakeEntry(latencyMs: 500));
        audit.Record(MakeEntry(latencyMs: 2000));

        var hist = audit.GetLatencyHistogram();
        Assert.Equal(1, hist.Under1ms);
        Assert.Equal(1, hist.Under5ms);
        Assert.Equal(1, hist.Under50ms);
        Assert.Equal(1, hist.Under200ms);
        Assert.Equal(1, hist.Under1s);
        Assert.Equal(1, hist.Over1s);
    }

    [Fact]
    public void ExportJsonExportsAllEntries()
    {
        var audit = new UnifiedAuditTrail();
        audit.Record(MakeEntry(ip: "1.1.1.1"));
        audit.Record(MakeEntry(ip: "2.2.2.2"));

        var parsed = System.Text.Json.JsonSerializer.Deserialize<List<object>>(audit.ExportJson());
        Assert.Equal(2, parsed!.Count);
    }

    [Fact]
    public void BoundedStorageEvictsOldest10PercentWhenMaxEntriesReached()
    {
        var audit = new UnifiedAuditTrail(maxEntries: 100);
        for (int i = 0; i < 110; i++)
        {
            audit.Record(MakeEntry(eventId: $"evt_{i}"));
        }

        var stats = audit.GetStats();
        Assert.True(stats.Total <= 110);
        Assert.True(stats.Total > 90);
    }

    [Fact]
    public void ResetClearsAllEntriesAndStats()
    {
        var audit = new UnifiedAuditTrail();
        audit.Record(MakeEntry());
        audit.Record(MakeEntry());
        Assert.Equal(2, audit.GetStats().Total);

        audit.Reset();
        Assert.Equal(0, audit.GetStats().Total);
        Assert.Equal(0, audit.GetStats().InternalDecisions);
    }

    [Fact]
    public void OnEntryCallbackFiresForEachRecordedEntry()
    {
        var received = new List<UnifiedAuditEntry>();
        var audit = new UnifiedAuditTrail(onEntry: received.Add);
        audit.Record(MakeEntry());
        audit.Record(MakeEntry());
        Assert.Equal(2, received.Count);
    }

    [Fact]
    public void OnEntryCallbackSurvivesErrors()
    {
        var audit = new UnifiedAuditTrail(onEntry: _ => throw new InvalidOperationException("callback error"));
        audit.Record(MakeEntry()); // must not throw
        Assert.Equal(1, audit.GetStats().Total);
    }

    [Fact]
    public void DedupMergesExternalOverInternal()
    {
        var audit = new UnifiedAuditTrail();
        audit.Record(MakeEntry(eventId: "evt_dup", source: AuditSource.Internal, decision: "allow"));
        audit.Record(MakeEntry(eventId: "evt_dup", source: AuditSource.External, decision: "block"));

        var results = audit.Query();
        Assert.Single(results);
        Assert.Equal(AuditSource.Hybrid, results[0].Source);
        Assert.Equal("block", results[0].Decision);
    }

    [Fact]
    public void DedupSkipsDuplicateInternalWithoutMerging()
    {
        var audit = new UnifiedAuditTrail();
        audit.Record(MakeEntry(eventId: "evt_dup2", source: AuditSource.Internal, decision: "allow"));
        audit.Record(MakeEntry(eventId: "evt_dup2", source: AuditSource.Internal, decision: "block"));

        var results = audit.Query();
        Assert.Single(results);
        Assert.Equal("allow", results[0].Decision);
    }
}
