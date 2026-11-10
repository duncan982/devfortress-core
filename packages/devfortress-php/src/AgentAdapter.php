<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

use Throwable;

/**
 * DevFortress Agent Security Adapter (IP-C1).
 *
 * Wraps Client::trackEvent() for AI agent tool invocations. Intercepts
 * agent_id, tool_name, and input_summary from LangChain/LangGraph tool
 * calls, OpenAI function calling, or raw HTTP-based agent tool invocations.
 * Mirrors packages/devfortress-sdk/src/agent.ts.
 *
 * Unlike the Node SDK's synchronous df.observe() (which can return a
 * server-decided flagged verdict on the same call), the PHP SDK's Tier 1
 * Client queues events in memory and delivers them in batches via flush()
 * (or the Laravel middleware's terminate() hook, after the response has
 * gone out) — there is no per-call server round trip here to carry a
 * flagged verdict back, so this adapter has no onFlagged callback, matching
 * the Go and Ruby SDKs' same adaptation for the same reason. The event
 * shape (agent_id, tool_name, input_summary, framework, session tracking)
 * matches the Node SDK field-for-field.
 */
final class AgentAdapter
{
    private const MAX_TRACKED_SESSIONS = 10_000;

    private readonly string $agentName;
    /** @var array<string, int> */
    private array $sessionToolCounts = [];

    public function __construct(
        private readonly Client $client,
        private readonly string $agentId,
        ?string $agentName = null,
        private readonly string $agentIp = '127.0.0.1',
        private readonly int $maxInputSummaryLength = 256,
        private readonly bool $sanitizeInputs = true,
    ) {
        AgentId::validate($agentId);
        $this->agentName = $agentName ?? $agentId;
    }

    /**
     * Queue an observation of an AI agent tool invocation.
     *
     * @param array<string, mixed>|null $input
     * @param array<string, mixed>|null $meta
     */
    public function observeToolCall(
        string $tool,
        ?array $input = null,
        ?int $durationMs = null,
        ?string $model = null,
        string $framework = 'custom',
        ?array $meta = null,
        ?string $sessionId = null,
    ): void {
        $summary = $this->summarizeInput($input);

        $sid = $sessionId ?? 'default';
        $count = ($this->sessionToolCounts[$sid] ?? 0) + 1;
        $this->sessionToolCounts[$sid] = $count;

        $metadata = [
            'agent_id' => $this->agentId,
            'agent_name' => $this->agentName,
            'tool_name' => $tool,
            'input_summary' => $summary,
            'duration_ms' => $durationMs,
            'model' => $model,
            'framework' => $framework,
            'session_tool_count' => $count,
            'session_id' => $sessionId,
            'event_category' => 'agent_tool_call',
        ];
        if ($meta !== null) {
            $metadata = [...$metadata, ...$meta];
        }

        $this->client->trackEvent([
            'eventType' => 'custom',
            'method' => 'TOOL_CALL',
            'path' => "/agent/{$this->agentId}/tool/{$tool}",
            'ip' => $this->agentIp,
            'userAgent' => "DevFortress-Agent/{$this->agentName}",
            'severity' => 'LOW',
            'metadata' => $metadata,
        ]);
    }

    /**
     * Convenience wrapper for a LangChain/LangGraph tool call.
     *
     * @param array<string, mixed> $toolInput
     */
    public function observeLangChainTool(
        string $toolName,
        array $toolInput,
        ?string $sessionId = null,
        ?string $model = null,
        ?int $durationMs = null,
    ): void {
        $this->observeToolCall(
            tool: $toolName,
            input: $toolInput,
            durationMs: $durationMs,
            model: $model,
            framework: 'langchain',
            sessionId: $sessionId,
        );
    }

    /** Convenience wrapper extracting from an OpenAI tool_calls entry. */
    public function observeOpenAIToolCall(
        string $functionName,
        string $argumentsJson,
        ?string $sessionId = null,
        ?string $model = null,
        ?int $durationMs = null,
    ): void {
        try {
            $decoded = json_decode($argumentsJson, true, flags: JSON_THROW_ON_ERROR);
            /** @var array<string, mixed> $parsed */
            $parsed = is_array($decoded) ? $decoded : ['raw' => $argumentsJson];
        } catch (Throwable) {
            $parsed = ['raw' => $argumentsJson];
        }

        $this->observeToolCall(
            tool: $functionName,
            input: $parsed,
            durationMs: $durationMs,
            model: $model,
            framework: 'openai',
            sessionId: $sessionId,
        );
    }

    /**
     * Observe a raw HTTP tool call (e.g. an agent calling an external API).
     *
     * @param array<string, mixed>|null $meta
     */
    public function observeHttpToolCall(
        string $url,
        string $method,
        ?int $statusCode = null,
        ?int $durationMs = null,
        ?string $sessionId = null,
        ?array $meta = null,
    ): void {
        $this->observeToolCall(
            tool: 'http:' . strtoupper($method),
            input: ['url' => $url, 'status_code' => $statusCode],
            durationMs: $durationMs,
            framework: 'raw_http',
            meta: $meta,
            sessionId: $sessionId,
        );
    }

    /** Track the start of an agent session (task/conversation). */
    public function trackSessionStart(string $sessionId, ?string $taskDescription = null): void
    {
        if (count($this->sessionToolCounts) >= self::MAX_TRACKED_SESSIONS) {
            unset($this->sessionToolCounts[array_key_first($this->sessionToolCounts)]);
        }
        $this->sessionToolCounts[$sessionId] = 0;

        $this->client->trackEvent([
            'eventType' => 'custom',
            'method' => 'SESSION_START',
            'path' => "/agent/{$this->agentId}/session/{$sessionId}",
            'ip' => $this->agentIp,
            'userAgent' => "DevFortress-Agent/{$this->agentName}",
            'severity' => 'LOW',
            'metadata' => [
                'agent_id' => $this->agentId,
                'session_id' => $sessionId,
                'task_description' => $taskDescription,
                'event_category' => 'agent_session_start',
            ],
        ]);
    }

    /** Track the end of an agent session with summary metrics. */
    public function trackSessionEnd(
        string $sessionId,
        ?int $totalTools = null,
        ?int $durationMs = null,
        ?bool $success = null,
    ): void {
        $toolCount = $this->sessionToolCounts[$sessionId] ?? 0;
        unset($this->sessionToolCounts[$sessionId]);

        $this->client->trackEvent([
            'eventType' => 'custom',
            'method' => 'SESSION_END',
            'path' => "/agent/{$this->agentId}/session/{$sessionId}",
            'ip' => $this->agentIp,
            'userAgent' => "DevFortress-Agent/{$this->agentName}",
            'severity' => 'LOW',
            'metadata' => [
                'agent_id' => $this->agentId,
                'session_id' => $sessionId,
                'total_tools' => $totalTools ?? $toolCount,
                'total_duration_ms' => $durationMs,
                'success' => $success,
                'event_category' => 'agent_session_end',
            ],
        ]);
    }

    public function getSessionToolCount(string $sessionId): int
    {
        return $this->sessionToolCounts[$sessionId] ?? 0;
    }

    /** @param array<string, mixed>|null $input */
    private function summarizeInput(?array $input): string
    {
        if ($input === null) {
            return '{}';
        }

        $summary = [];
        foreach ($input as $key => $val) {
            $keyStr = (string) $key;
            if ($val === null) {
                $summary[$keyStr] = 'null';
            } elseif (is_string($val)) {
                $lower = strtolower($keyStr);
                if ($this->sanitizeInputs && (
                    str_contains($lower, 'key') || str_contains($lower, 'token')
                    || str_contains($lower, 'secret') || str_contains($lower, 'password')
                )) {
                    $summary[$keyStr] = '[REDACTED]';
                } else {
                    $summary[$keyStr] = strlen($val) > 64 ? substr($val, 0, 61) . '...' : $val;
                }
            } elseif (is_int($val) || is_float($val) || is_bool($val)) {
                $summary[$keyStr] = $val === true ? 'true' : ($val === false ? 'false' : (string) $val);
            } elseif (is_array($val) && array_is_list($val)) {
                $summary[$keyStr] = 'Array(' . count($val) . ')';
            } else {
                $summary[$keyStr] = '{...}';
            }
        }

        $str = json_encode($summary, JSON_THROW_ON_ERROR);
        $maxLen = $this->maxInputSummaryLength;

        return strlen($str) > $maxLen ? substr($str, 0, $maxLen - 3) . '...' : $str;
    }
}
