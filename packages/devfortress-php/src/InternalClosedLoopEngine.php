<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/**
 * DevFortress SDK — Internal Closed-Loop Protection Engine (TODO 407 port).
 *
 * Port of packages/devfortress-sdk/src/internal-closed-loop-engine.ts's
 * `InternalClosedLoopEngine`, following the same shape as this SDK
 * family's already-completed Python port
 * (packages/devfortress-python/src/devfortress/internal_closed_loop_engine.py).
 * Request/result/action/audit shapes are plain arrays with
 * `@phpstan-type` annotations, matching this package's own convention for
 * this kind of module (see {@see GraduatedRateLimiter}, {@see ColdStartDetector}),
 * not Node/Python's dataclass-style value objects.
 *
 * Three tiers:
 *
 *   Tier 1: Deterministic rule engine (<1ms) — regex, scanner signature,
 *           sensitive-file, credential-stuffing, and agent-tool rules.
 *           Independently verified against Node's actual V8 regex objects
 *           (not ported by analogy from Python) — see the session report
 *           for the full node-vs-php verification matrix. No PCRE syntax
 *           changes were needed beyond delimiter choice (`#...#` instead
 *           of `/.../ `, purely to avoid escaping literal `/` in the
 *           path-traversal/sensitive-file patterns) — every pattern,
 *           including the edge cases (the `/.env` overlap between
 *           path_traversal and sensitive_file_access, and the
 *           `q=UNION SELECT...` non-match because there is no
 *           whitespace/string-start immediately before UNION), reproduced
 *           Node's exact match/no-match behaviour.
 *   Tier 2: Optional custom scorer — a PHP `callable` the caller supplies.
 *           Unimplemented/pass-through by default: no scorer is wired in
 *           unless the caller passes one; `evaluate()` simply skips Tier 2
 *           entirely in that case (same as Node/Python's behaviour when no
 *           scorer is configured). PHP has no real async, so this is
 *           always a synchronous callable (`callable(array): float`),
 *           matching this SDK's existing stdlib-only, no-async-framework
 *           convention (see {@see ResponseWebhookClient}).
 *   Tier 3: Relay callback — fires the caller-supplied `onRelay` callable
 *           for non-'allow' decisions when `enableExternalRelay` is true
 *           (hybrid mode only). This engine has no HTTP client or
 *           platform credentials of its own by design; the caller's relay
 *           callback does the actual platform call, same as Node's
 *           `onRelay`/`relayInternalDecisionToPlatform` and Python's
 *           `on_relay`.
 *
 * State (blocked IPs/users/sessions, quarantined agents, rate-limiter
 * entries, audit log) is bounded in-memory via {@see BoundedMap}, lives
 * for the engine instance's lifetime, and is never persisted — matching
 * Node's BoundedMap-backed design exactly.
 *
 * @phpstan-type InternalCLDecision 'allow'|'block'|'rate_limit'|'challenge'|'quarantine'
 * @phpstan-type InternalCLRequest array{
 *     ip: string,
 *     method: string,
 *     path: string,
 *     userAgent?: string|null,
 *     userId?: string|null,
 *     sessionId?: string|null,
 *     body?: string|null,
 *     query?: string|null,
 *     headers?: array<string, string>,
 *     agentId?: string|null,
 *     toolName?: string|null,
 *     timestamp?: float|null,
 * }
 * @phpstan-type InternalCLAction array{
 *     type: string,
 *     target: string,
 *     reason: string,
 *     ttlSeconds: int,
 *     timestamp: float,
 *     eventId: string,
 * }
 * @phpstan-type InternalCLResult array{
 *     decision: InternalCLDecision,
 *     score: float,
 *     tier: int,
 *     matchedRules: list<string>,
 *     evaluationTimeUs: float,
 *     actions: list<InternalCLAction>,
 *     eventId: string,
 * }
 * @phpstan-type InternalCLAuditEntry array{
 *     eventId: string,
 *     timestamp: float,
 *     ip: string,
 *     decision: InternalCLDecision,
 *     score: float,
 *     tier: int,
 *     matchedRules: list<string>,
 *     userId: ?string,
 *     agentId: ?string,
 *     path: string,
 *     method: string,
 * }
 * @phpstan-type InternalCLRuleDef array{
 *     name: string,
 *     description: string,
 *     severity: string,
 *     score: float,
 *     decision: InternalCLDecision,
 *     match: \Closure(InternalCLRequest): bool,
 *     enabled: bool,
 * }
 */
final class InternalClosedLoopEngine
{
    // ── Default Attack Pattern Rules (Tier 1) — verified byte-for-byte
    // against Node's actual V8 regex objects (see class docblock). ───────

    /** @var list<string> */
    private const SQLI_STRICT = [
        '#(?:^|\s)(?:UNION\s+(?:ALL\s+)?SELECT|DROP\s+TABLE|INSERT\s+INTO|UPDATE\s+[a-zA-Z0-9_]+\s+SET|DELETE\s+FROM)(?:\s|$)#i',
        '#(?:\'|")\s*OR\s+(?:\d+\s*=\s*\d+|\'[^\']*\'\s*=\s*\'[^\']*\'|"[^"]*"\s*=\s*"[^"]*")#i',
        '#(?:\'|")\s*;\s*(?:--|/\*)#',
        '#(\bxp_\w+)#i',
    ];

    /** @var list<string> */
    private const SQLI_MODERATE = [
        '#(/\*.*\*/)#',
        '#(\bEXEC\b|\bEXECUTE\b)\s*\(#i',
    ];

    /** @var list<string> */
    private const XSS = [
        '#<script[\s>]#i',
        '#javascript\s*:#i',
        '#on(load|error|click|mouseover|submit|focus|blur)\s*=#i',
        '#(<iframe|<object|<embed|<applet)#i',
        '#(document\.(cookie|write|location))#i',
        '#(window\.(location|open))#i',
    ];

    /** @var list<string> */
    private const PATH_TRAVERSAL = [
        '#\.\./#',
        '#\.\.%2[fF]#',
        '#\.\.\\\\$#',
        '#%2e%2e[%/\\\\]#i',
        '#/etc/(passwd|shadow|hosts)#',
        '#/proc/self#',
        '#(/\.env|/\.git|/\.ssh)#',
    ];

    /** @var list<string> */
    private const SCANNER_SIGNATURES = [
        '#sqlmap#i', '#nikto#i', '#nmap#i', '#dirbuster#i', '#gobuster#i', '#wpscan#i',
        '#burp\s*suite#i', '#acunetix#i', '#nessus#i', '#masscan#i', '#zgrab#i', '#nuclei#i',
    ];

    /** @var list<string> — only /phpmyadmin/ carries the case-insensitive flag in Node's own set. */
    private const SENSITIVE_FILE = [
        '#/\.env#', '#/\.git#', '#/\.ssh#', '#/wp-admin#', '#/wp-login#',
        '#/phpmyadmin#i', '#/admin\.php#', '#/\.htaccess#', '#/\.htpasswd#',
        '#/server-status#', '#/actuator#', '#/debug/#',
    ];

    /** @var list<string> */
    private const AUTH_PATHS = ['/login', '/signin', '/auth', '/api/auth', '/api/login', '/oauth/token'];

    /** @var list<string> */
    private const DANGEROUS_TOOLS = ['shell_exec', 'eval', 'exec', 'rm', 'sudo', 'chmod', 'kill'];

    /** @var BoundedMap<array{expiresAt: float, reason: string}> */
    private BoundedMap $blockedIPs;
    /** @var BoundedMap<array{expiresAt: float, reason: string}> */
    private BoundedMap $blockedUsers;
    /** @var BoundedMap<array{expiresAt: float, reason: string}> */
    private BoundedMap $blockedSessions;
    /** @var BoundedMap<array{reason: string, timestamp: float}> */
    private BoundedMap $quarantinedAgents;
    /** @var BoundedMap<array{timestamps: list<float>, blocked: bool}> */
    private BoundedMap $rateLimiter;

    /** @var list<InternalCLAuditEntry> */
    private array $auditLog = [];

    /** @var list<InternalCLRuleDef> */
    private array $rules = [];

    private int $eventCounter = 0;

    // callable, not Closure, is not a valid PHP property type — these are
    // accepted as `callable` constructor parameters (per the task's own
    // "PHP callable" wording) and normalized to \Closure for storage.
    private readonly ?\Closure $tier2Scorer;
    private readonly ?\Closure $onAction;
    private readonly ?\Closure $onRelay;

    /**
     * @param 'closed'|'open' $failMode Fail-closed (block on error) or fail-open (allow on error). Default: 'closed'.
     * @param bool $enableExternalRelay Enable Tier 3 relay to external platform. Default: false (air-gap).
     * @param (callable(InternalCLRequest): float)|null $tier2Scorer Optional Tier-2 scorer. Unset = Tier 2 skipped entirely.
     * @param (callable(InternalCLAction): void)|null $onAction Callback fired for every action executed.
     * @param (callable(InternalCLResult, InternalCLRequest): void)|null $onRelay Tier-3 relay target (hybrid mode only).
     */
    public function __construct(
        private readonly string $failMode = 'closed',
        private readonly bool $enableExternalRelay = false,
        int $maxBlockedEntries = 10_000,
        int $maxRateLimitEntries = 50_000,
        private readonly int $maxAuditEntries = 100_000,
        private readonly int $defaultBlockTtlSeconds = 3600,
        ?callable $tier2Scorer = null,
        private readonly float $blockThreshold = 85.0,
        private readonly float $rateLimitThreshold = 60.0,
        private readonly int $rateLimitMax = 100,
        private readonly float $rateLimitWindowSeconds = 60.0,
        private readonly bool $debug = false,
        ?callable $onAction = null,
        ?callable $onRelay = null,
    ) {
        $this->tier2Scorer = $tier2Scorer === null ? null : \Closure::fromCallable($tier2Scorer);
        $this->onAction = $onAction === null ? null : \Closure::fromCallable($onAction);
        $this->onRelay = $onRelay === null ? null : \Closure::fromCallable($onRelay);

        $this->blockedIPs = new BoundedMap($maxBlockedEntries);
        $this->blockedUsers = new BoundedMap($maxBlockedEntries);
        $this->blockedSessions = new BoundedMap($maxBlockedEntries);
        $this->quarantinedAgents = new BoundedMap($maxBlockedEntries);
        $this->rateLimiter = new BoundedMap($maxRateLimitEntries);

        $this->registerDefaultRules();
        $this->log('info', "Internal Closed-Loop Engine initialized (failMode={$this->failMode})");
    }

    // ── Public API ──────────────────────────────────────────────────────

    /**
     * Evaluate a request through the 3-tier engine. Call this for every
     * inbound request, before it reaches the application — the defining
     * behaviour of internal mode is that this never needs a platform
     * round-trip to produce a decision.
     *
     * @param InternalCLRequest $req
     * @return InternalCLResult
     */
    public function evaluate(array $req): array
    {
        $req = $this->normalizeRequest($req);
        $start = hrtime(true);
        $now = $req['timestamp'] ?? microtime(true);
        $eventId = $this->generateEventId();

        try {
            $preCheck = $this->checkBlocked($req, $now);
            if ($preCheck !== null) {
                [$decision, $reason] = $preCheck;
                $result = [
                    'decision' => $decision,
                    'score' => 100.0,
                    'tier' => 1,
                    'matchedRules' => [$reason],
                    'evaluationTimeUs' => $this->elapsedUs($start),
                    'actions' => [],
                    'eventId' => $eventId,
                ];
                $this->recordAudit($result, $req);

                return $result;
            }

            [$tier1Decision, $tier1Score, $tier1Rules] = $this->evaluateTier1($req);
            if ($tier1Decision !== 'allow') {
                $actions = $this->executeActions($tier1Decision, $tier1Rules, $req, $eventId, $now);
                $result = [
                    'decision' => $tier1Decision,
                    'score' => $tier1Score,
                    'tier' => 1,
                    'matchedRules' => $tier1Rules,
                    'evaluationTimeUs' => $this->elapsedUs($start),
                    'actions' => $actions,
                    'eventId' => $eventId,
                ];
                $this->recordAudit($result, $req);
                if ($this->enableExternalRelay) {
                    $this->relayToExternal($result, $req);
                }

                return $result;
            }

            if ($this->checkRateLimit($req['ip'], $now)) {
                $actions = $this->executeActions('rate_limit', ['rate_limit_exceeded'], $req, $eventId, $now);
                $result = [
                    'decision' => 'rate_limit',
                    'score' => 65.0,
                    'tier' => 1,
                    'matchedRules' => ['rate_limit_exceeded'],
                    'evaluationTimeUs' => $this->elapsedUs($start),
                    'actions' => $actions,
                    'eventId' => $eventId,
                ];
                $this->recordAudit($result, $req);

                return $result;
            }

            $this->recordRequest($req['ip'], $now);

            // ─── Tier 2: optional custom scorer — unimplemented/pass-through
            // by default. Skipped entirely when no scorer is configured. ───
            if ($this->tier2Scorer !== null) {
                $score = (float) ($this->tier2Scorer)($req);

                if ($score >= $this->blockThreshold) {
                    $actions = $this->executeActions('block', ['tier2_ml_score'], $req, $eventId, $now);
                    $result = [
                        'decision' => 'block',
                        'score' => $score,
                        'tier' => 2,
                        'matchedRules' => ['tier2_ml_score'],
                        'evaluationTimeUs' => $this->elapsedUs($start),
                        'actions' => $actions,
                        'eventId' => $eventId,
                    ];
                    $this->recordAudit($result, $req);
                    if ($this->enableExternalRelay) {
                        $this->relayToExternal($result, $req);
                    }

                    return $result;
                }

                if ($score >= $this->rateLimitThreshold) {
                    $result = [
                        'decision' => 'rate_limit',
                        'score' => $score,
                        'tier' => 2,
                        'matchedRules' => ['tier2_ml_elevated'],
                        'evaluationTimeUs' => $this->elapsedUs($start),
                        'actions' => [],
                        'eventId' => $eventId,
                    ];
                    $this->recordAudit($result, $req);

                    return $result;
                }
            }

            return [
                'decision' => 'allow',
                'score' => 0.0,
                'tier' => 1,
                'matchedRules' => [],
                'evaluationTimeUs' => $this->elapsedUs($start),
                'actions' => [],
                'eventId' => $eventId,
            ];
        } catch (\Throwable $error) {
            $this->log('error', 'Evaluation error: ' . $error->getMessage());

            if ($this->failMode === 'closed') {
                return [
                    'decision' => 'block',
                    'score' => 100.0,
                    'tier' => 1,
                    'matchedRules' => ['fail_closed_error'],
                    'evaluationTimeUs' => $this->elapsedUs($start),
                    'actions' => [],
                    'eventId' => $eventId,
                ];
            }

            return [
                'decision' => 'allow',
                'score' => 0.0,
                'tier' => 1,
                'matchedRules' => ['fail_open_error'],
                'evaluationTimeUs' => $this->elapsedUs($start),
                'actions' => [],
                'eventId' => $eventId,
            ];
        }
    }

    public function blockIP(string $ip, string $reason, ?int $ttlSeconds = null): void
    {
        $ttl = $ttlSeconds ?? $this->defaultBlockTtlSeconds;
        $this->blockedIPs->set($ip, ['expiresAt' => microtime(true) + $ttl, 'reason' => $reason]);
        $this->log('info', "IP blocked: {$ip} — {$reason} (TTL: {$ttl}s)");
    }

    public function unblockIP(string $ip): bool
    {
        $existed = $this->blockedIPs->has($ip);
        $this->blockedIPs->delete($ip);
        if ($existed) {
            $this->log('info', "IP unblocked: {$ip}");
        }

        return $existed;
    }

    public function blockUser(string $userId, string $reason, ?int $ttlSeconds = null): void
    {
        $ttl = $ttlSeconds ?? $this->defaultBlockTtlSeconds;
        $this->blockedUsers->set($userId, ['expiresAt' => microtime(true) + $ttl, 'reason' => $reason]);
        $this->log('info', "User blocked: {$userId} — {$reason}");
    }

    public function blockSession(string $sessionId, string $reason, ?int $ttlSeconds = null): void
    {
        $ttl = $ttlSeconds ?? $this->defaultBlockTtlSeconds;
        $this->blockedSessions->set($sessionId, ['expiresAt' => microtime(true) + $ttl, 'reason' => $reason]);
        $this->log('info', "Session blocked: {$sessionId} — {$reason}");
    }

    public function quarantineAgent(string $agentId, string $reason): void
    {
        $this->quarantinedAgents->set($agentId, ['reason' => $reason, 'timestamp' => microtime(true)]);
        $this->log('info', "Agent quarantined: {$agentId} — {$reason}");
    }

    public function unquarantineAgent(string $agentId): bool
    {
        $existed = $this->quarantinedAgents->has($agentId);
        $this->quarantinedAgents->delete($agentId);
        if ($existed) {
            $this->log('info', "Agent unquarantined: {$agentId}");
        }

        return $existed;
    }

    public function isIPBlocked(string $ip): bool
    {
        $entry = $this->blockedIPs->get($ip);
        if ($entry === null) {
            return false;
        }
        if (microtime(true) > $entry['expiresAt']) {
            $this->blockedIPs->delete($ip);

            return false;
        }

        return true;
    }

    public function isAgentQuarantined(string $agentId): bool
    {
        return $this->quarantinedAgents->has($agentId);
    }

    /** @param InternalCLRuleDef $rule */
    public function addRule(array $rule): void
    {
        $this->rules[] = $rule;
        $this->log('debug', "Rule added: {$rule['name']}");
    }

    public function removeRule(string $name): bool
    {
        foreach ($this->rules as $i => $rule) {
            if ($rule['name'] === $name) {
                array_splice($this->rules, $i, 1);
                $this->log('debug', "Rule removed: {$name}");

                return true;
            }
        }

        return false;
    }

    /** @return list<array{name: string, description: string, severity: string, score: float, decision: InternalCLDecision, enabled: bool}> */
    public function getRules(): array
    {
        return array_map(
            static fn (array $r): array => [
                'name' => $r['name'],
                'description' => $r['description'],
                'severity' => $r['severity'],
                'score' => $r['score'],
                'decision' => $r['decision'],
                'enabled' => $r['enabled'],
            ],
            $this->rules,
        );
    }

    /** @return list<InternalCLAuditEntry> */
    public function getAuditLog(int $limit = 100): array
    {
        return array_slice($this->auditLog, -$limit);
    }

    /** @return array{blockedIPs: int, blockedUsers: int, blockedSessions: int, quarantinedAgents: int, rateLimitEntries: int, auditLogSize: int, rulesCount: int, failMode: string} */
    public function getStats(): array
    {
        return [
            'blockedIPs' => $this->blockedIPs->size(),
            'blockedUsers' => $this->blockedUsers->size(),
            'blockedSessions' => $this->blockedSessions->size(),
            'quarantinedAgents' => $this->quarantinedAgents->size(),
            'rateLimitEntries' => $this->rateLimiter->size(),
            'auditLogSize' => count($this->auditLog),
            'rulesCount' => count($this->rules),
            'failMode' => $this->failMode,
        ];
    }

    /** @param list<array{ip: string, reason: string, ttlSeconds?: int}> $entries */
    public function importBlockedIPs(array $entries): int
    {
        $count = 0;
        foreach ($entries as $entry) {
            $this->blockIP($entry['ip'], $entry['reason'], $entry['ttlSeconds'] ?? null);
            $count++;
        }

        return $count;
    }

    /** Reset all state. For testing. */
    public function reset(): void
    {
        $this->blockedIPs->clear();
        $this->blockedUsers->clear();
        $this->blockedSessions->clear();
        $this->quarantinedAgents->clear();
        $this->rateLimiter->clear();
        $this->auditLog = [];
        $this->eventCounter = 0;
    }

    /**
     * Lightweight, synchronous, zero-network content check reusing the
     * same Tier 1 patterns as {@see registerDefaultRules()}. Mirrors
     * Node's exported `matchesKnownAttackPattern` (Option B, 2026-08-27).
     */
    public static function matchesKnownAttackPattern(?string $path = null, ?string $userAgent = null): bool
    {
        if ($path !== null && $path !== '') {
            foreach (self::SQLI_STRICT as $p) {
                if (preg_match($p, $path) === 1) {
                    return true;
                }
            }
            foreach (self::SQLI_MODERATE as $p) {
                if (preg_match($p, $path) === 1) {
                    return true;
                }
            }
            foreach (self::XSS as $p) {
                if (preg_match($p, $path) === 1) {
                    return true;
                }
            }
            foreach (self::PATH_TRAVERSAL as $p) {
                if (preg_match($p, $path) === 1) {
                    return true;
                }
            }
        }
        if ($userAgent !== null && $userAgent !== '') {
            foreach (self::SCANNER_SIGNATURES as $p) {
                if (preg_match($p, $userAgent) === 1) {
                    return true;
                }
            }
        }

        return false;
    }

    // ── Private: request normalization ──────────────────────────────────

    /**
     * @param InternalCLRequest $req
     * @return InternalCLRequest
     */
    private function normalizeRequest(array $req): array
    {
        $req['userAgent'] ??= null;
        $req['userId'] ??= null;
        $req['sessionId'] ??= null;
        $req['body'] ??= null;
        $req['query'] ??= null;
        $req['headers'] ??= [];
        $req['agentId'] ??= null;
        $req['toolName'] ??= null;
        $req['timestamp'] ??= null;

        return $req;
    }

    // ── Private: pre-check / Tier 1 / rate limit ─────────────────────────

    /**
     * @param InternalCLRequest $req
     * @return array{0: InternalCLDecision, 1: string}|null
     */
    private function checkBlocked(array $req, float $now): ?array
    {
        $ipBlock = $this->blockedIPs->get($req['ip']);
        if ($ipBlock !== null) {
            if ($now > $ipBlock['expiresAt']) {
                $this->blockedIPs->delete($req['ip']);
            } else {
                return ['block', "ip_blocked:{$ipBlock['reason']}"];
            }
        }

        if (!empty($req['userId'])) {
            $userBlock = $this->blockedUsers->get($req['userId']);
            if ($userBlock !== null) {
                if ($now > $userBlock['expiresAt']) {
                    $this->blockedUsers->delete($req['userId']);
                } else {
                    return ['block', "user_blocked:{$userBlock['reason']}"];
                }
            }
        }

        if (!empty($req['sessionId'])) {
            $sessionBlock = $this->blockedSessions->get($req['sessionId']);
            if ($sessionBlock !== null) {
                if ($now > $sessionBlock['expiresAt']) {
                    $this->blockedSessions->delete($req['sessionId']);
                } else {
                    return ['block', "session_blocked:{$sessionBlock['reason']}"];
                }
            }
        }

        if (!empty($req['agentId']) && $this->quarantinedAgents->has($req['agentId'])) {
            return ['quarantine', "agent_quarantined:{$req['agentId']}"];
        }

        return null;
    }

    /**
     * @param InternalCLRequest $req
     * @return array{0: InternalCLDecision, 1: float, 2: list<string>}
     */
    private function evaluateTier1(array $req): array
    {
        $matchedRules = [];
        $maxScore = 0.0;
        $decision = 'allow';

        foreach ($this->rules as $rule) {
            if (!$rule['enabled']) {
                continue;
            }
            try {
                if (($rule['match'])($req)) {
                    $matchedRules[] = $rule['name'];
                    if ($rule['score'] > $maxScore) {
                        $maxScore = $rule['score'];
                        $decision = $rule['decision'];
                    }
                }
            } catch (\Throwable) {
                // Individual rule errors should not crash the engine.
                $this->log('error', "Rule {$rule['name']} threw an error");
            }
        }

        return [$decision, $maxScore, $matchedRules];
    }

    private function checkRateLimit(string $ip, float $now): bool
    {
        $entry = $this->rateLimiter->get($ip);
        if ($entry === null) {
            return false;
        }

        $windowStart = $now - $this->rateLimitWindowSeconds;
        $entry['timestamps'] = array_values(array_filter($entry['timestamps'], static fn (float $t): bool => $t > $windowStart));

        if (count($entry['timestamps']) >= $this->rateLimitMax) {
            $entry['blocked'] = true;
            $this->rateLimiter->set($ip, $entry);

            return true;
        }

        $this->rateLimiter->set($ip, $entry);

        return false;
    }

    private function recordRequest(string $ip, float $now): void
    {
        $entry = $this->rateLimiter->get($ip) ?? ['timestamps' => [], 'blocked' => false];
        $entry['timestamps'][] = $now;
        $this->rateLimiter->set($ip, $entry);
    }

    /**
     * @param InternalCLDecision $decision
     * @param list<string> $matchedRules
     * @param InternalCLRequest $req
     * @return list<InternalCLAction>
     */
    private function executeActions(string $decision, array $matchedRules, array $req, string $eventId, float $now): array
    {
        $actions = [];
        $ttl = $this->defaultBlockTtlSeconds;
        $reason = implode(', ', $matchedRules);

        if ($decision === 'block' || $decision === 'quarantine') {
            $this->blockedIPs->set($req['ip'], ['expiresAt' => $now + $ttl, 'reason' => $reason]);
            $actions[] = [
                'type' => 'block_ip',
                'target' => $req['ip'],
                'reason' => $reason,
                'ttlSeconds' => $ttl,
                'timestamp' => $now,
                'eventId' => $eventId,
            ];

            if (!empty($req['sessionId'])) {
                $this->blockedSessions->set($req['sessionId'], ['expiresAt' => $now + $ttl, 'reason' => $reason]);
                $actions[] = [
                    'type' => 'block_session',
                    'target' => $req['sessionId'],
                    'reason' => $reason,
                    'ttlSeconds' => $ttl,
                    'timestamp' => $now,
                    'eventId' => $eventId,
                ];
            }

            if (!empty($req['agentId'])) {
                $this->quarantinedAgents->set($req['agentId'], ['reason' => $reason, 'timestamp' => $now]);
                $actions[] = [
                    'type' => 'quarantine_agent',
                    'target' => $req['agentId'],
                    'reason' => $reason,
                    'ttlSeconds' => 0,
                    'timestamp' => $now,
                    'eventId' => $eventId,
                ];
            }
        }

        if ($this->onAction !== null) {
            foreach ($actions as $action) {
                try {
                    ($this->onAction)($action);
                } catch (\Throwable) {
                    $this->log('error', "onAction callback error for {$action['type']}");
                }
            }
        }

        return $actions;
    }

    /**
     * @param InternalCLResult $result
     * @param InternalCLRequest $req
     */
    private function recordAudit(array $result, array $req): void
    {
        if (count($this->auditLog) >= $this->maxAuditEntries) {
            array_splice($this->auditLog, 0, max(1, (int) floor($this->maxAuditEntries * 0.1)));
        }

        $this->auditLog[] = [
            'eventId' => $result['eventId'],
            'timestamp' => $req['timestamp'] ?? microtime(true),
            'ip' => $req['ip'],
            'decision' => $result['decision'],
            'score' => $result['score'],
            'tier' => $result['tier'],
            'matchedRules' => $result['matchedRules'],
            'userId' => $req['userId'] ?? null,
            'agentId' => $req['agentId'] ?? null,
            'path' => $req['path'],
            'method' => $req['method'],
        ];
    }

    /**
     * @param InternalCLResult $result
     * @param InternalCLRequest $req
     */
    private function relayToExternal(array $result, array $req): void
    {
        // Tier 3: relay via the caller-supplied onRelay callback. This
        // engine has no HTTP client or platform credentials of its own by
        // design — the caller (e.g. Client::relayInternalDecisionToPlatform)
        // does the actual platform call. Synchronous: PHP has no real
        // async, matching this SDK's other callback-based integration
        // points.
        $this->log('debug', "Tier 3 relay: {$result['eventId']} -> external platform");
        if ($this->onRelay === null) {
            return;
        }
        try {
            ($this->onRelay)($result, $req);
        } catch (\Throwable $e) {
            $this->log('error', "onRelay callback error for {$result['eventId']}: " . $e->getMessage());
        }
    }

    private function generateEventId(): string
    {
        $this->eventCounter++;
        $ts = base_convert((string) (int) round(microtime(true) * 1000), 10, 36);
        $counter = str_pad(base_convert((string) $this->eventCounter, 10, 36), 4, '0', STR_PAD_LEFT);
        $rand = str_pad(base_convert((string) random_int(0, 0xFFFF), 10, 36), 4, '0', STR_PAD_LEFT);

        return "icl_{$ts}_{$counter}_{$rand}";
    }

    private function elapsedUs(int $startNs): float
    {
        return (hrtime(true) - $startNs) / 1000.0;
    }

    private function registerDefaultRules(): void
    {
        $this->rules[] = [
            'name' => 'sql_injection',
            'description' => 'Detects SQL injection patterns context-aware (strict on path/query, moderate on body)',
            'severity' => 'critical',
            'score' => 95.0,
            'decision' => 'block',
            'enabled' => true,
            'match' =>
                /** @param InternalCLRequest $req */
                static function (array $req): bool {
                $strictTargets = array_values(array_filter([$req['path'] ?? null, $req['query'] ?? null], static fn ($t) => $t !== null && $t !== ''));
                foreach ($strictTargets as $t) {
                    foreach (self::SQLI_STRICT as $p) {
                        if (preg_match($p, $t) === 1) {
                            return true;
                        }
                    }
                }
                foreach ($strictTargets as $t) {
                    foreach (self::SQLI_MODERATE as $p) {
                        if (preg_match($p, $t) === 1) {
                            return true;
                        }
                    }
                }

                $bodyTargets = array_values(array_filter(
                    [$req['body'] ?? null, ...array_values($req['headers'] ?? [])],
                    static fn ($t) => $t !== null && $t !== '',
                ));
                foreach ($bodyTargets as $t) {
                    foreach (self::SQLI_STRICT as $p) {
                        if (preg_match($p, $t) === 1) {
                            return true;
                        }
                    }
                }

                return false;
            },
        ];

        $this->rules[] = [
            'name' => 'xss_attempt',
            'description' => 'Detects cross-site scripting patterns',
            'severity' => 'high',
            'score' => 90.0,
            'decision' => 'block',
            'enabled' => true,
            'match' =>
                /** @param InternalCLRequest $req */
                static function (array $req): bool {
                $targets = array_values(array_filter([$req['path'] ?? null, $req['query'] ?? null, $req['body'] ?? null], static fn ($t) => $t !== null && $t !== ''));
                foreach ($targets as $t) {
                    foreach (self::XSS as $p) {
                        if (preg_match($p, $t) === 1) {
                            return true;
                        }
                    }
                }

                return false;
            },
        ];

        $this->rules[] = [
            'name' => 'path_traversal',
            'description' => 'Detects directory traversal attempts',
            'severity' => 'high',
            'score' => 90.0,
            'decision' => 'block',
            'enabled' => true,
            'match' =>
                /** @param InternalCLRequest $req */
                static function (array $req): bool {
                $targets = array_values(array_filter([$req['path'] ?? null, $req['query'] ?? null], static fn ($t) => $t !== null && $t !== ''));
                foreach ($targets as $t) {
                    foreach (self::PATH_TRAVERSAL as $p) {
                        if (preg_match($p, $t) === 1) {
                            return true;
                        }
                    }
                }

                return false;
            },
        ];

        $this->rules[] = [
            'name' => 'scanner_detected',
            'description' => 'Detects known vulnerability scanner user agents',
            'severity' => 'medium',
            'score' => 75.0,
            'decision' => 'block',
            'enabled' => true,
            'match' =>
                /** @param InternalCLRequest $req */
                static function (array $req): bool {
                if (empty($req['userAgent'])) {
                    return false;
                }
                foreach (self::SCANNER_SIGNATURES as $p) {
                    if (preg_match($p, $req['userAgent']) === 1) {
                        return true;
                    }
                }

                return false;
            },
        ];

        $this->rules[] = [
            'name' => 'sensitive_file_access',
            'description' => 'Detects access to sensitive files (.env, .git, wp-admin, etc.)',
            'severity' => 'high',
            'score' => 85.0,
            'decision' => 'block',
            'enabled' => true,
            'match' =>
                /** @param InternalCLRequest $req */
                static function (array $req): bool {
                foreach (self::SENSITIVE_FILE as $p) {
                    if (preg_match($p, $req['path']) === 1) {
                        return true;
                    }
                }

                return false;
            },
        ];

        $this->rules[] = [
            'name' => 'credential_stuffing_pattern',
            'description' => 'Detects credential stuffing via POST to auth endpoints',
            'severity' => 'high',
            'score' => 80.0,
            'decision' => 'rate_limit',
            'enabled' => true,
            'match' =>
                /** @param InternalCLRequest $req */
                static function (array $req): bool {
                if ($req['method'] !== 'POST') {
                    return false;
                }
                $pathLower = strtolower($req['path']);
                foreach (self::AUTH_PATHS as $p) {
                    if (str_contains($pathLower, $p)) {
                        return true;
                    }
                }

                return false;
            },
        ];

        $this->rules[] = [
            'name' => 'agent_unsanctioned_tool',
            'description' => 'Detects agent attempting to use dangerous tools',
            'severity' => 'critical',
            'score' => 95.0,
            'decision' => 'quarantine',
            'enabled' => true,
            'match' =>
                /** @param InternalCLRequest $req */
                static function (array $req): bool {
                if (empty($req['agentId']) || empty($req['toolName'])) {
                    return false;
                }

                return in_array(strtolower($req['toolName']), self::DANGEROUS_TOOLS, true);
            },
        ];
    }

    private function log(string $level, string $message): void
    {
        if (!$this->debug && $level === 'debug') {
            return;
        }
        // error_log(), not STDOUT/STDERR: those constants are undefined
        // under PHP-FPM (only defined for the CLI SAPI), and this engine
        // runs inside a web request under Laravel/FPM, not just CLI.
        if (in_array($level, ['error', 'warn'], true) || $this->debug) {
            error_log("[DevFortress ICL] {$message}");
        }
    }
}
