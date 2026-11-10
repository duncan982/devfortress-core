<?php

declare(strict_types=1);

namespace DevFortress\Sdk\Tests;

use DevFortress\Sdk\UnifiedAuditTrail;
use PHPUnit\Framework\TestCase;

final class UnifiedAuditTrailTest extends TestCase
{
    private function makeEntry(array $overrides = []): array
    {
        return [...[
            'eventId' => 'evt_' . bin2hex(random_bytes(4)),
            'timestamp' => microtime(true),
            'source' => 'internal',
            'tier' => 1,
            'decision' => 'allow',
            'score' => 10,
            'severity' => 'low',
            'latencyMs' => 0.5,
            'ip' => '192.168.1.1',
            'path' => '/api/test',
            'method' => 'GET',
            'matchedRules' => [],
        ], ...$overrides];
    }

    public function testRecordAndRetrieveEntries(): void
    {
        $audit = new UnifiedAuditTrail();
        $audit->record($this->makeEntry(['ip' => '10.0.0.1']));
        $audit->record($this->makeEntry(['ip' => '10.0.0.2']));
        self::assertCount(2, $audit->query());
    }

    public function testFilterBySource(): void
    {
        $audit = new UnifiedAuditTrail();
        $audit->record($this->makeEntry(['source' => 'internal']));
        $audit->record($this->makeEntry(['source' => 'external']));
        $audit->record($this->makeEntry(['source' => 'hybrid']));

        self::assertCount(1, $audit->query(source: 'internal'));
        self::assertCount(1, $audit->query(source: 'external'));
        self::assertCount(1, $audit->query(source: 'hybrid'));
    }

    public function testFilterByDecision(): void
    {
        $audit = new UnifiedAuditTrail();
        $audit->record($this->makeEntry(['decision' => 'allow']));
        $audit->record($this->makeEntry(['decision' => 'block']));
        $audit->record($this->makeEntry(['decision' => 'rate_limit']));

        self::assertCount(1, $audit->query(decision: 'block'));
    }

    public function testFilterByMinScore(): void
    {
        $audit = new UnifiedAuditTrail();
        $audit->record($this->makeEntry(['score' => 20]));
        $audit->record($this->makeEntry(['score' => 60]));
        $audit->record($this->makeEntry(['score' => 90]));

        self::assertCount(2, $audit->query(minScore: 50));
    }

    public function testFilterBySince(): void
    {
        $audit = new UnifiedAuditTrail();
        $now = microtime(true);
        $audit->record($this->makeEntry(['timestamp' => $now - 10]));
        $audit->record($this->makeEntry(['timestamp' => $now - 5]));
        $audit->record($this->makeEntry(['timestamp' => $now]));

        self::assertCount(2, $audit->query(since: $now - 7));
    }

    public function testLimitResults(): void
    {
        $audit = new UnifiedAuditTrail();
        for ($i = 0; $i < 50; $i++) {
            $audit->record($this->makeEntry());
        }
        self::assertCount(10, $audit->query(limit: 10));
    }

    public function testCombineMultipleFilters(): void
    {
        $audit = new UnifiedAuditTrail();
        $audit->record($this->makeEntry(['source' => 'internal', 'decision' => 'block', 'score' => 85]));
        $audit->record($this->makeEntry(['source' => 'internal', 'decision' => 'allow', 'score' => 10]));
        $audit->record($this->makeEntry(['source' => 'external', 'decision' => 'block', 'score' => 90]));

        $results = $audit->query(source: 'internal', decision: 'block', minScore: 80);
        self::assertCount(1, $results);
        self::assertSame(85, $results[0]['score']);
    }

    public function testStatsCountsDecisionsBySource(): void
    {
        $audit = new UnifiedAuditTrail();
        $audit->record($this->makeEntry(['source' => 'internal']));
        $audit->record($this->makeEntry(['source' => 'internal']));
        $audit->record($this->makeEntry(['source' => 'external']));
        $audit->record($this->makeEntry(['source' => 'hybrid']));

        $stats = $audit->getStats();
        self::assertSame(4, $stats['total']);
        self::assertSame(2, $stats['internalDecisions']);
        self::assertSame(1, $stats['externalDecisions']);
        self::assertSame(1, $stats['hybridDecisions']);
    }

    public function testStatsCountsBlocksAllowsRateLimits(): void
    {
        $audit = new UnifiedAuditTrail();
        $audit->record($this->makeEntry(['decision' => 'block']));
        $audit->record($this->makeEntry(['decision' => 'allow']));
        $audit->record($this->makeEntry(['decision' => 'allow']));
        $audit->record($this->makeEntry(['decision' => 'rate_limit']));

        $stats = $audit->getStats();
        self::assertSame(1, $stats['totalBlocks']);
        self::assertSame(2, $stats['totalAllows']);
        self::assertSame(1, $stats['totalRateLimits']);
    }

    public function testAverageLatencies(): void
    {
        $audit = new UnifiedAuditTrail();
        $audit->record($this->makeEntry(['source' => 'internal', 'latencyMs' => 0.5]));
        $audit->record($this->makeEntry(['source' => 'internal', 'latencyMs' => 1.5]));
        $audit->record($this->makeEntry(['source' => 'external', 'latencyMs' => 100]));
        $audit->record($this->makeEntry(['source' => 'external', 'latencyMs' => 200]));

        $stats = $audit->getStats();
        self::assertSame(1, $stats['avgInternalLatencyMs']);
        self::assertSame(150, $stats['avgExternalLatencyMs']);
    }

    public function testDecisionDistribution(): void
    {
        $audit = new UnifiedAuditTrail();
        $audit->record($this->makeEntry(['source' => 'internal', 'decision' => 'allow']));
        $audit->record($this->makeEntry(['source' => 'internal', 'decision' => 'allow']));
        $audit->record($this->makeEntry(['source' => 'internal', 'decision' => 'block']));
        $audit->record($this->makeEntry(['source' => 'external', 'decision' => 'allow']));

        $dist = $audit->getDecisionDistribution();
        self::assertSame(2, $dist['internal:allow']);
        self::assertSame(1, $dist['internal:block']);
        self::assertSame(1, $dist['external:allow']);
    }

    public function testLatencyHistogramBucketsCorrectly(): void
    {
        $audit = new UnifiedAuditTrail();
        $audit->record($this->makeEntry(['latencyMs' => 0.3]));
        $audit->record($this->makeEntry(['latencyMs' => 2]));
        $audit->record($this->makeEntry(['latencyMs' => 30]));
        $audit->record($this->makeEntry(['latencyMs' => 100]));
        $audit->record($this->makeEntry(['latencyMs' => 500]));
        $audit->record($this->makeEntry(['latencyMs' => 2000]));

        $hist = $audit->getLatencyHistogram();
        self::assertSame(1, $hist['under1ms']);
        self::assertSame(1, $hist['under5ms']);
        self::assertSame(1, $hist['under50ms']);
        self::assertSame(1, $hist['under200ms']);
        self::assertSame(1, $hist['under1s']);
        self::assertSame(1, $hist['over1s']);
    }

    public function testExportJsonExportsAllEntries(): void
    {
        $audit = new UnifiedAuditTrail();
        $audit->record($this->makeEntry(['ip' => '1.1.1.1']));
        $audit->record($this->makeEntry(['ip' => '2.2.2.2']));

        $parsed = json_decode($audit->exportJson(), true);
        self::assertCount(2, $parsed);
    }

    public function testExportJsonSince(): void
    {
        $audit = new UnifiedAuditTrail();
        $now = microtime(true);
        $audit->record($this->makeEntry(['timestamp' => $now - 10]));
        $audit->record($this->makeEntry(['timestamp' => $now]));

        $parsed = json_decode($audit->exportJson(since: $now - 5), true);
        self::assertCount(1, $parsed);
    }

    public function testBoundedStorageEvictsOldest10PercentWhenMaxEntriesReached(): void
    {
        $audit = new UnifiedAuditTrail(maxEntries: 100);
        for ($i = 0; $i < 110; $i++) {
            $audit->record($this->makeEntry(['eventId' => "evt_{$i}"]));
        }

        $stats = $audit->getStats();
        self::assertLessThanOrEqual(110, $stats['total']);
        self::assertGreaterThan(90, $stats['total']);
    }

    public function testResetClearsAllEntriesAndStats(): void
    {
        $audit = new UnifiedAuditTrail();
        $audit->record($this->makeEntry());
        $audit->record($this->makeEntry());
        self::assertSame(2, $audit->getStats()['total']);

        $audit->reset();
        self::assertSame(0, $audit->getStats()['total']);
        self::assertSame(0, $audit->getStats()['internalDecisions']);
    }

    public function testOnEntryCallbackFiresForEachRecordedEntry(): void
    {
        $received = [];
        $audit = new UnifiedAuditTrail(onEntry: function (array $e) use (&$received): void {
            $received[] = $e;
        });
        $audit->record($this->makeEntry());
        $audit->record($this->makeEntry());

        self::assertCount(2, $received);
    }

    public function testOnEntryCallbackSurvivesErrors(): void
    {
        $audit = new UnifiedAuditTrail(onEntry: static function (): void {
            throw new \RuntimeException('callback error');
        });

        $audit->record($this->makeEntry()); // must not throw
        self::assertSame(1, $audit->getStats()['total']);
    }

    public function testDedupMergesExternalOverInternalWithinWindow(): void
    {
        $audit = new UnifiedAuditTrail();
        $audit->record($this->makeEntry(['eventId' => 'evt_dup', 'source' => 'internal', 'decision' => 'allow']));
        $audit->record($this->makeEntry(['eventId' => 'evt_dup', 'source' => 'external', 'decision' => 'block']));

        $results = $audit->query();
        self::assertCount(1, $results);
        self::assertSame('hybrid', $results[0]['source']);
        self::assertSame('block', $results[0]['decision']);
    }

    public function testDedupSkipsDuplicateInternalWithoutMerging(): void
    {
        $audit = new UnifiedAuditTrail();
        $audit->record($this->makeEntry(['eventId' => 'evt_dup2', 'source' => 'internal', 'decision' => 'allow']));
        $audit->record($this->makeEntry(['eventId' => 'evt_dup2', 'source' => 'internal', 'decision' => 'block']));

        $results = $audit->query();
        self::assertCount(1, $results);
        self::assertSame('allow', $results[0]['decision']);
    }
}
