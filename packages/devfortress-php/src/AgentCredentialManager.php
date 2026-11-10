<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

use Throwable;

/**
 * Agent Credential Manager (IP-C2). Extends the core credential isolation
 * system for AI agent credentials: createAgentAlias(), revokeAgentAccess(),
 * quarantineAgent(). Mirrors packages/devfortress-sdk/src/agent-security.ts.
 */
final class AgentCredentialManager
{
    /** @var array<string, list<AgentCredentialAliasData>> */
    private array $credentials = [];
    /** @var array<string, array{reason: string, at: int}> */
    private array $quarantines = [];

    public function __construct(
        private readonly CredentialIsolationManager $tokenManager,
        private readonly ?CacheAdapterInterface $cache = null,
    ) {
    }

    /**
     * Create an alias for an agent credential (API key, OAuth token, etc.).
     * The real credential never leaves the client application.
     *
     * @param array{containerId?: string, expectedEgressPath?: string, expectedProcessSignature?: string}|null $executionContext
     */
    public function createAgentAlias(
        string $realCredential,
        string $agentId,
        string $credentialType,
        int $ttlSeconds = 7200,
        ?array $executionContext = null,
    ): string {
        AgentId::validate($agentId);
        $alias = $this->tokenManager->createAlias($realCredential, $agentId, $ttlSeconds);

        $data = new AgentCredentialAliasData($alias, $agentId, $credentialType, self::nowMs(), $executionContext);
        $this->credentials[$agentId] ??= [];
        $this->credentials[$agentId][] = $data;

        if ($this->cache !== null) {
            try {
                $existing = $this->cache->get("agent:creds:{$agentId}");
                /** @var list<array<string, mixed>> $list */
                $list = $existing !== null ? json_decode($existing, true, flags: JSON_THROW_ON_ERROR) : [];
                $list[] = $data->toArray();
                $this->cache->set("agent:creds:{$agentId}", json_encode($list, JSON_THROW_ON_ERROR), $ttlSeconds);
            } catch (Throwable) {
                // In-memory is already set
            }
        }

        return $alias;
    }

    /** Revoke ALL credentials for an agent (IP-C2). */
    public function revokeAgentAccess(string $agentId, string $reason = 'active_threat'): int
    {
        $creds = $this->credentials[$agentId] ?? [];
        $revokedCount = 0;

        foreach ($creds as $cred) {
            try {
                $this->tokenManager->revokeByAlias($cred->alias, $reason, $agentId);
                $revokedCount++;
            } catch (Throwable) {
                // Continue revoking remaining credentials
            }
        }

        unset($this->credentials[$agentId], $this->quarantines[$agentId]);

        if ($this->cache !== null) {
            try {
                $this->cache->del("agent:creds:{$agentId}");
                $this->cache->del("agent:quarantine:{$agentId}");
            } catch (Throwable) {
                // Best-effort
            }
        }

        return $revokedCount;
    }

    /**
     * Quarantine an agent (IP-C2) — suspend tool access but preserve session
     * for forensics. Unlike revocation, quarantine is reversible and the
     * session data remains intact.
     */
    public function quarantineAgent(string $agentId, string $reason): void
    {
        $at = self::nowMs();
        $this->quarantines[$agentId] = ['reason' => $reason, 'at' => $at];

        foreach ($this->credentials[$agentId] ?? [] as $cred) {
            $cred->quarantined = true;
            $cred->quarantineReason = $reason;
            $cred->quarantinedAt = $at;
        }

        if ($this->cache !== null) {
            try {
                $this->cache->set(
                    "agent:quarantine:{$agentId}",
                    json_encode(['reason' => $reason, 'at' => $at], JSON_THROW_ON_ERROR),
                    86_400,
                );
            } catch (Throwable) {
                // In-memory is set
            }
        }
    }

    /**
     * Lift quarantine for an agent, restoring normal tool access. Rejects
     * if the agent isn't currently quarantined — reinstatement is only
     * meaningful as the reverse of an active quarantine, not a silent no-op.
     */
    public function unquarantineAgent(string $agentId): void
    {
        if (!array_key_exists($agentId, $this->quarantines)) {
            throw new \RuntimeException("Agent \"{$agentId}\" is not currently quarantined — nothing to reinstate.");
        }

        unset($this->quarantines[$agentId]);
        foreach ($this->credentials[$agentId] ?? [] as $cred) {
            $cred->quarantined = false;
            $cred->quarantineReason = null;
            $cred->quarantinedAt = null;
        }

        if ($this->cache !== null) {
            try {
                $this->cache->del("agent:quarantine:{$agentId}");
            } catch (Throwable) {
                // Best-effort
            }
        }
    }

    public function isQuarantined(string $agentId): bool
    {
        return array_key_exists($agentId, $this->quarantines);
    }

    /** @return array{reason: string, at: int}|null */
    public function getQuarantineDetails(string $agentId): ?array
    {
        return $this->quarantines[$agentId] ?? null;
    }

    /** @return list<AgentCredentialAliasData> */
    public function getAgentCredentials(string $agentId): array
    {
        return $this->credentials[$agentId] ?? [];
    }

    private static function nowMs(): int
    {
        return (int) round(microtime(true) * 1000);
    }
}
