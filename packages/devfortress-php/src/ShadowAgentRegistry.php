<?php


declare(strict_types=1);

namespace DevFortress\Sdk;

/**
 * DevFortress SDK — Shadow Agent Registry.
 *
 * Detects and tracks unauthorized ("shadow") AI agents that operate
 * without proper registration. Maintains a registry of known agents
 * and flags unregistered agent-like behavior. Mirrors
 * packages/devfortress-sdk/src/shadow-agent-registry.ts.
 *
 * @phpstan-type RegisteredAgent array{agentId: string, name: string, registeredAt: int, lastHeartbeat: int, owner: string, permissions: list<string>, active: bool}
 * @phpstan-type ShadowAgentDetection array{detected: bool, agentFingerprint: string, indicators: list<string>, confidence: float, recommendation: string, matchedPatterns: list<string>}
 * @phpstan-type AgentRegistryStats array{registeredCount: int, activeCount: int, shadowDetections: int, blockedShadows: int}
 */
final class ShadowAgentRegistry
{
    /** @var list<string> */
    private const DEFAULT_AGENT_PATTERNS = [
        'automated request pattern (>100 req/min)',
        'consistent timing between requests (<50ms variance)',
        'sequential resource enumeration',
        'user-agent indicates bot/automation',
        'no mouse/keyboard entropy in session',
        'API-only access (no page loads)',
    ];

    private readonly int $heartbeatTimeoutMs;
    /** @var list<string> */
    private readonly array $agentPatterns;
    private readonly bool $autoBlock;

    /** @var array<string, RegisteredAgent> */
    private array $registry = [];
    /** @var array<string, ShadowAgentDetection> */
    private array $shadowDetections = [];
    /** @var AgentRegistryStats */
    private array $stats = [
        'registeredCount' => 0,
        'activeCount' => 0,
        'shadowDetections' => 0,
        'blockedShadows' => 0,
    ];

    /** @param list<string>|null $agentPatterns */
    public function __construct(
        ?int $heartbeatTimeoutMs = null,
        ?array $agentPatterns = null,
        ?bool $autoBlock = null,
    ) {
        $this->heartbeatTimeoutMs = $heartbeatTimeoutMs ?? 300_000;
        $this->agentPatterns = $agentPatterns ?? self::DEFAULT_AGENT_PATTERNS;
        $this->autoBlock = $autoBlock ?? false;
    }

    /**
     * Register a known agent.
     *
     * @param array{agentId: string, name: string, owner: string, permissions: list<string>} $agent
     * @return RegisteredAgent
     */
    public function register(array $agent): array
    {
        if (getenv('FEATURE_PLATFORM_INTEL') === 'false') {
            return [
                'agentId' => $agent['agentId'],
                'name' => $agent['name'],
                'owner' => $agent['owner'],
                'permissions' => $agent['permissions'],
                'registeredAt' => 0,
                'lastHeartbeat' => 0,
                'active' => false,
            ];
        }

        $registered = [
            'agentId' => $agent['agentId'],
            'name' => $agent['name'],
            'owner' => $agent['owner'],
            'permissions' => $agent['permissions'],
            'registeredAt' => self::nowMs(),
            'lastHeartbeat' => self::nowMs(),
            'active' => true,
        ];
        $this->registry[$agent['agentId']] = $registered;
        $this->stats['registeredCount']++;
        $this->stats['activeCount']++;

        return $registered;
    }

    /** Record a heartbeat from a registered agent. */
    public function heartbeat(string $agentId): bool
    {
        if (!isset($this->registry[$agentId])) {
            return false;
        }
        $this->registry[$agentId]['lastHeartbeat'] = self::nowMs();
        $this->registry[$agentId]['active'] = true;

        return true;
    }

    /**
     * Check if a request source is a registered agent or a shadow.
     *
     * @param list<string> $indicators
     * @return ShadowAgentDetection
     */
    public function detect(string $fingerprint, array $indicators): array
    {
        if (getenv('FEATURE_PLATFORM_INTEL') === 'false') {
            return [
                'detected' => false,
                'agentFingerprint' => $fingerprint,
                'indicators' => [],
                'confidence' => 0.0,
                'recommendation' => 'monitor',
                'matchedPatterns' => [],
            ];
        }

        // Check if any registered agent matches this fingerprint.
        foreach ($this->registry as $agent) {
            if ($agent['agentId'] === $fingerprint && $agent['active']) {
                return [
                    'detected' => false,
                    'agentFingerprint' => $fingerprint,
                    'indicators' => [],
                    'confidence' => 0.0,
                    'recommendation' => 'monitor',
                    'matchedPatterns' => [],
                ];
            }
        }

        // Check indicators against known agent patterns.
        $matchedPatterns = array_values(array_filter($this->agentPatterns, static function (string $pattern) use ($indicators): bool {
            $patternKey = strtolower(trim(explode('(', $pattern, 2)[0]));
            foreach ($indicators as $indicator) {
                if (str_contains(strtolower($indicator), $patternKey)) {
                    return true;
                }
            }

            return false;
        }));

        $confidence = min(1.0, count($matchedPatterns) / 3);
        $detected = $confidence > 0.3;

        if ($detected) {
            $this->stats['shadowDetections']++;
            if ($this->autoBlock && $confidence > 0.7) {
                $this->stats['blockedShadows']++;
            }
        }

        $result = [
            'detected' => $detected,
            'agentFingerprint' => $fingerprint,
            'indicators' => $indicators,
            'confidence' => $confidence,
            'recommendation' => $confidence > 0.7
                ? ($this->autoBlock ? 'block' : 'register')
                : 'monitor',
            'matchedPatterns' => $matchedPatterns,
        ];
        if ($detected) {
            $this->shadowDetections[$fingerprint] = $result;
        }

        return $result;
    }

    /**
     * Prune inactive agents (no heartbeat within timeout).
     *
     * @return list<string>
     */
    public function pruneInactive(): array
    {
        $cutoff = self::nowMs() - $this->heartbeatTimeoutMs;
        $pruned = [];
        foreach ($this->registry as $id => $agent) {
            if ($agent['lastHeartbeat'] < $cutoff) {
                $this->registry[$id]['active'] = false;
                $this->stats['activeCount']--;
                $pruned[] = $id;
            }
        }

        return $pruned;
    }

    /** @return AgentRegistryStats */
    public function getStats(): array
    {
        return $this->stats;
    }

    /** @return list<RegisteredAgent> */
    public function getRegistered(): array
    {
        return array_values($this->registry);
    }

    /**
     * The most recent shadow-agent detection recorded for a fingerprint, if
     * any. Node's ShadowAgentRegistry keeps this same per-fingerprint
     * detection history internally (its own private `shadowDetections` map
     * in shadow-agent-registry.ts) without ever exposing a getter for it
     * either; this accessor exists so the history has a real read site in
     * PHP (PHPStan's property.onlyWritten check, unlike tsc, flags a
     * write-only property as an error) rather than being silently dead,
     * the same accommodation MultiHopTrustChain::getCascadeTimeoutMs()
     * makes for its own otherwise-unread field.
     *
     * @return ShadowAgentDetection|null
     */
    public function getShadowDetection(string $fingerprint): ?array
    {
        return $this->shadowDetections[$fingerprint] ?? null;
    }

    private static function nowMs(): int
    {
        return (int) round(microtime(true) * 1000);
    }
}
