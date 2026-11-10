<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/** Shared statistics helpers for AgentBaselineEngine and AgentAnomalyDetector. */
final class AgentBehaviorMath
{
    private function __construct()
    {
    }

    /** @param list<string> $items */
    public static function shannonEntropy(array $items): float
    {
        if ($items === []) {
            return 0.0;
        }
        $freq = [];
        foreach ($items as $item) {
            $freq[$item] = ($freq[$item] ?? 0) + 1;
        }
        $total = count($items);
        $entropy = 0.0;
        foreach ($freq as $count) {
            $p = $count / $total;
            if ($p > 0) {
                $entropy -= $p * log($p, 2);
            }
        }

        return $entropy;
    }
}
