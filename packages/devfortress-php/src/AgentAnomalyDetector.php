<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

use Throwable;

/**
 * Agent Anomaly Detector (IP-C4), with unsanctioned-tool scope enforcement
 * (IP-C5) integrated here for convenience — mirrors the Go and Ruby SDKs'
 * merged AgentAnomalyDetector, since scope enforcement is only ever
 * consumed from inside analyzeToolCall() anyway. Mirrors
 * packages/devfortress-sdk/src/agent-security.ts's AgentAnomalyDetector +
 * AgentScopeEnforcer.
 */
final class AgentAnomalyDetector
{
    /** @var list<callable(AgentAnomalySignal): void> */
    private array $anomalyHandlers = [];
    /** @var array<string, list<string>> credentialAlias => agentIds seen using it */
    private array $credentialUsage = [];
    /** @var array<string, AgentScopeDefinition> */
    private array $scopes = [];

    public function __construct(private readonly AgentBaselineEngine $baselineEngine)
    {
    }

    /** @param callable(AgentAnomalySignal): void $handler */
    public function onAnomaly(callable $handler): void
    {
        $this->anomalyHandlers[] = $handler;
    }

    /**
     * Register the sanctioned tool scope for an agent (IP-C5). In strict
     * mode, any tool invocation outside allowedTools fires a critical
     * anomaly immediately.
     *
     * @param list<string> $allowedTools
     */
    public function defineAgentScope(string $agentId, array $allowedTools, bool $strictMode = true): AgentScopeDefinition
    {
        $now = self::nowMs();
        $createdAt = array_key_exists($agentId, $this->scopes) ? $this->scopes[$agentId]->createdAt : $now;
        $scope = new AgentScopeDefinition($agentId, $allowedTools, $strictMode, $createdAt, $now);
        $this->scopes[$agentId] = $scope;

        return $scope;
    }

    /** Whether toolName is within agentId's defined scope. */
    public function isToolAllowed(string $agentId, string $toolName): bool
    {
        $scope = $this->scopes[$agentId] ?? null;
        if ($scope === null) {
            return true; // No scope defined — allow by default
        }
        if (!$scope->strictMode) {
            return true; // Non-strict mode — log but allow
        }

        return in_array($toolName, $scope->allowedTools, true);
    }

    public function getScope(string $agentId): ?AgentScopeDefinition
    {
        return $this->scopes[$agentId] ?? null;
    }

    public function removeScope(string $agentId): void
    {
        unset($this->scopes[$agentId]);
    }

    /** @param list<string> $tools */
    public function addAllowedTools(string $agentId, array $tools): void
    {
        $scope = $this->scopes[$agentId] ?? null;
        if ($scope === null) {
            $this->defineAgentScope($agentId, $tools, true);

            return;
        }
        $scope->allowedTools = array_values(array_unique([...$scope->allowedTools, ...$tools]));
        $scope->updatedAt = self::nowMs();
    }

    /** @param list<string> $tools */
    public function removeAllowedTools(string $agentId, array $tools): void
    {
        $scope = $this->scopes[$agentId] ?? null;
        if ($scope === null) {
            return;
        }
        $scope->allowedTools = array_values(array_diff($scope->allowedTools, $tools));
        $scope->updatedAt = self::nowMs();
    }

    /**
     * Analyze a tool call for anomalies against the agent's baseline.
     *
     * @return list<AgentAnomalySignal>
     */
    public function analyzeToolCall(string $agentId, string $toolName, int $dataBytes = 0, ?string $credentialAlias = null): array
    {
        $signals = [];
        $baseline = $this->baselineEngine->getBaseline($agentId);

        // IP-C5 scope check (integrated here for convenience)
        $scope = $this->scopes[$agentId] ?? null;
        if ($scope !== null && $scope->strictMode && !in_array($toolName, $scope->allowedTools, true)) {
            $signal = new AgentAnomalySignal(
                type: 'unsanctioned_tool',
                agentId: $agentId,
                severity: 'critical',
                description: "Agent {$agentId} invoked unsanctioned tool \"{$toolName}\". Allowed: [" . implode(', ', $scope->allowedTools) . ']',
                detectedAt: self::nowMs(),
                details: ['tool' => $toolName, 'allowedTools' => $scope->allowedTools],
            );
            $signals[] = $signal;
            $this->emitSignal($signal);
        }

        if ($baseline === null) {
            return $signals;
        }

        // IP-C4.1: Tool invocation scope deviation
        if ($baseline->topTools !== [] && !in_array($toolName, $baseline->topTools, true)) {
            $signal = new AgentAnomalySignal(
                type: 'scope_deviation',
                agentId: $agentId,
                severity: 'medium',
                description: "Agent {$agentId} invoked tool \"{$toolName}\" outside its baseline tool set",
                detectedAt: self::nowMs(),
                details: ['tool' => $toolName, 'baselineTools' => $baseline->topTools],
            );
            $signals[] = $signal;
            $this->emitSignal($signal);
        }

        // IP-C4.3: Data volume anomaly (3σ deviation)
        if ($dataBytes > 0) {
            $sessions = $this->baselineEngine->sessionsFor($agentId);
            $volumes = array_map(static fn (AgentSessionRecord $s) => $s->totalDataBytes, $sessions);
            if ($this->baselineEngine->is3SigmaDeviation($volumes, (float) $dataBytes)) {
                $signal = new AgentAnomalySignal(
                    type: 'data_volume_anomaly',
                    agentId: $agentId,
                    severity: 'high',
                    description: "Agent {$agentId} data volume {$dataBytes}B is 3σ deviation from baseline avg " . round($baseline->avgDataVolumeBytes) . 'B',
                    detectedAt: self::nowMs(),
                    details: ['dataBytes' => $dataBytes, 'baselineAvg' => $baseline->avgDataVolumeBytes],
                );
                $signals[] = $signal;
                $this->emitSignal($signal);
            }
        }

        // IP-C4.4: Cross-agent credential sharing detection
        if ($credentialAlias !== null) {
            $agents = $this->credentialUsage[$credentialAlias] ?? [];
            if (!in_array($agentId, $agents, true)) {
                $agents[] = $agentId;
            }
            $this->credentialUsage[$credentialAlias] = $agents;

            if (count($agents) > 1) {
                $signal = new AgentAnomalySignal(
                    type: 'cross_agent_credential_sharing',
                    agentId: $agentId,
                    severity: 'critical',
                    description: 'Credential ' . substr($credentialAlias, 0, 16) . '... shared across ' . count($agents) . ' agents: [' . implode(', ', $agents) . ']',
                    detectedAt: self::nowMs(),
                    details: ['credentialAlias' => substr($credentialAlias, 0, 16) . '...', 'sharingAgents' => $agents],
                );
                $signals[] = $signal;
                $this->emitSignal($signal);
            }
        }

        return $signals;
    }

    /**
     * Analyze a completed session for sequence entropy anomaly (IP-C4.1).
     *
     * @return list<AgentAnomalySignal>
     */
    public function analyzeSession(AgentSessionRecord $record): array
    {
        $signals = [];
        $baseline = $this->baselineEngine->getBaseline($record->agentId);
        if ($baseline === null || $baseline->totalSessions < 5) {
            return $signals;
        }

        $sessionTools = array_map(static fn ($tc) => $tc['tool'], $record->toolCalls);
        $sessionEntropy = AgentBehaviorMath::shannonEntropy($sessionTools);
        $entropyDeviation = abs($sessionEntropy - $baseline->toolDiversityEntropy);

        if ($baseline->toolDiversityEntropy > 0 && ($entropyDeviation / $baseline->toolDiversityEntropy) > 0.5) {
            $deviationPercent = ($entropyDeviation / $baseline->toolDiversityEntropy) * 100;
            $signal = new AgentAnomalySignal(
                type: 'sequence_entropy_anomaly',
                agentId: $record->agentId,
                severity: 'high',
                description: sprintf(
                    'Agent %s session entropy %.2f deviates %d%% from baseline %.2f',
                    $record->agentId,
                    $sessionEntropy,
                    (int) round($deviationPercent),
                    $baseline->toolDiversityEntropy,
                ),
                detectedAt: self::nowMs(),
                details: [
                    'sessionEntropy' => $sessionEntropy,
                    'baselineEntropy' => $baseline->toolDiversityEntropy,
                    'deviationPercent' => $deviationPercent,
                ],
            );
            $signals[] = $signal;
            $this->emitSignal($signal);
        }

        return $signals;
    }

    private function emitSignal(AgentAnomalySignal $signal): void
    {
        foreach ($this->anomalyHandlers as $handler) {
            try {
                $handler($signal);
            } catch (Throwable) {
                // Handler errors don't block detection
            }
        }
    }

    private static function nowMs(): int
    {
        return (int) round(microtime(true) * 1000);
    }
}
