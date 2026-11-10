<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

use DevFortress\Sdk\Transport\CurlTransport;
use DevFortress\Sdk\Transport\TransportInterface;
use InvalidArgumentException;
use Throwable;

/**
 * DevFortress SDK — License Manager (CV-M1, CV-M4, CV-M7).
 *
 * Implements:
 * - CV-M1: Server-side license validation with 24h check interval and
 *   72h grace degradation
 * - CV-M4: ML model expiry (30-day staleness without platform sync)
 * - CV-M7: SDK anti-tampering HMAC signature verification
 *
 * Mirrors packages/devfortress-sdk/src/license-manager.ts. This is the
 * client-side half of TODO 321's fix: the platform's
 * POST /api/sdk/license-check endpoint already exists and already works —
 * before this port, PHP simply had no client for it at all, which is the
 * same silent-degradation bug class TODO 321 fixed on Node (a call that
 * 404s, or is never made, must never be allowed to degrade the SDK to
 * monitor-only without a visible log line). checkLicense() below always
 * logs the outcome — 'info' on success, 'warning' once the grace period
 * is exhausted and the SDK actually degrades, 'debug' for failures still
 * within grace — never silently.
 *
 * One deliberate translation for PHP's request-scoped execution model:
 * Node's init() starts its own unref'd setInterval to re-check every
 * checkIntervalMs. PHP has no persistent process to hang a timer off by
 * default, so there is no timer here — isCheckDue() exposes the same
 * "has the interval elapsed" decision for the host to act on (call
 * checkLicense() again from a cron job, a queue worker tick, or once per
 * incoming request), which is the idiomatic PHP equivalent of a
 * self-scheduling background timer. The CV-M1 state machine itself
 * (grace period, consecutive-failure counting, degradation) is unchanged.
 *
 * @phpstan-type LicenseState array{valid: bool, tier: string, lastCheckedAt: int, consecutiveFailures: int, degraded: bool, degradationReason: ?string}
 * @phpstan-type ModelState array{lastSyncedAt: int, modelVersion: string, expired: bool}
 */
final class LicenseManager
{
    private const DEFAULT_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24h
    private const DEFAULT_GRACE_PERIOD_MS = 72 * 60 * 60 * 1000; // 72h
    private const DEFAULT_MODEL_EXPIRY_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
    private const LICENSE_CHECK_TIMEOUT_SECONDS = 10.0;

    private readonly TransportInterface $transport;
    private readonly RequestSigner $signer;
    private readonly int $checkIntervalMs;
    private readonly int $gracePeriodMs;
    private readonly int $modelExpiryMs;
    private readonly ?string $integritySecret;
    private readonly ?LoggerInterface $logger;

    /** @var LicenseState */
    private array $licenseState = [
        'valid' => false,
        'tier' => 'starter',
        'lastCheckedAt' => 0,
        'consecutiveFailures' => 0,
        'degraded' => false,
        'degradationReason' => null,
    ];

    /** @var ModelState */
    private array $modelState;

    private bool $initialized = false;

    public function __construct(
        private readonly string $apiKey,
        private readonly string $endpoint,
        ?int $checkIntervalMs = null,
        ?int $gracePeriodMs = null,
        ?int $modelExpiryMs = null,
        ?string $integritySecret = null,
        ?LoggerInterface $logger = null,
        ?TransportInterface $transport = null,
    ) {
        if ($apiKey === '') {
            throw new InvalidArgumentException('DevFortress\Sdk\LicenseManager: an API key is required');
        }
        $this->checkIntervalMs = $checkIntervalMs ?? self::DEFAULT_CHECK_INTERVAL_MS;
        $this->gracePeriodMs = $gracePeriodMs ?? self::DEFAULT_GRACE_PERIOD_MS;
        $this->modelExpiryMs = $modelExpiryMs ?? self::DEFAULT_MODEL_EXPIRY_MS;
        $this->integritySecret = $integritySecret;
        $this->logger = $logger;
        $this->transport = $transport ?? new CurlTransport();
        $this->signer = new RequestSigner($apiKey);
        $this->modelState = [
            'lastSyncedAt' => self::nowMs(),
            'modelVersion' => 'embedded-v1',
            'expired' => false,
        ];
    }

    // ── CV-M1: License Validation ──────────────────────────────

    /**
     * Initialize the license manager: performs the initial license check.
     * Safe to call multiple times (no-op after the first call). See the
     * class doc comment for why there is no periodic timer here — call
     * checkLicense() again (guarded by isCheckDue() if desired) to get
     * the periodic re-validation Node schedules for itself.
     *
     * @return LicenseState
     */
    public function init(): array
    {
        if ($this->initialized) {
            return $this->licenseState;
        }
        $this->checkLicense();
        $this->initialized = true;

        return $this->licenseState;
    }

    /** Whether checkIntervalMs has elapsed since the last check (or none has ever run). */
    public function isCheckDue(): bool
    {
        if ($this->licenseState['lastCheckedAt'] === 0) {
            return true;
        }

        return (self::nowMs() - $this->licenseState['lastCheckedAt']) >= $this->checkIntervalMs;
    }

    /**
     * Perform a license check against the platform.
     * On failure, tracks consecutive failures and degrades after grace period.
     *
     * @return LicenseState
     */
    public function checkLicense(): array
    {
        $url = rtrim($this->endpoint, '/') . '/api/sdk/license-check';
        $body = self::encode([
            'sdkVersion' => Client::VERSION,
            'timestamp' => self::nowMs(),
            'integrity' => $this->computeIntegrityHash(),
        ]);

        try {
            // Signed with a key ID and a fresh nonce per attempt: the key is never sent.
            $headers = $this->signer->sign('POST', RequestSigner::requestTargetFromUrl($url), $body)
                + ['Content-Type' => 'application/json'];
            $response = $this->transport->send('POST', $url, $headers, $body, self::LICENSE_CHECK_TIMEOUT_SECONDS);

            if ($response->statusCode >= 200 && $response->statusCode < 300) {
                $data = self::decodeObject($response->body);
                $tier = $data['tier'] ?? null;
                $this->licenseState = [
                    'valid' => true,
                    'tier' => is_string($tier) ? $tier : $this->licenseState['tier'],
                    'lastCheckedAt' => self::nowMs(),
                    'consecutiveFailures' => 0,
                    'degraded' => false,
                    'degradationReason' => null,
                ];

                // CV-M4: Sync ML model freshness on successful license check.
                $modelVersion = $data['modelVersion'] ?? null;
                if (is_string($modelVersion) && $modelVersion !== '') {
                    $this->modelState = [
                        'lastSyncedAt' => self::nowMs(),
                        'modelVersion' => $modelVersion,
                        'expired' => false,
                    ];
                }

                $this->log('info', "License validated: tier={$this->licenseState['tier']}");
            } elseif ($response->statusCode === 402 || $response->statusCode === 403) {
                // Explicitly unauthorized/payment required.
                $this->licenseState = [
                    'valid' => false,
                    'tier' => 'starter',
                    'lastCheckedAt' => self::nowMs(),
                    'consecutiveFailures' => $this->licenseState['consecutiveFailures'] + 1,
                    'degraded' => true,
                    'degradationReason' => "License rejected: HTTP {$response->statusCode}",
                ];
                $this->log('warning', "License rejected: HTTP {$response->statusCode}");
            } else {
                // Server error — treat as transient failure.
                $this->handleCheckFailure("HTTP {$response->statusCode}");
            }
        } catch (Throwable $e) {
            $this->handleCheckFailure($e->getMessage());
        }

        return $this->licenseState;
    }

    private function handleCheckFailure(string $reason): void
    {
        $this->licenseState['consecutiveFailures']++;
        // If never successfully checked, start grace period from "now" (ported
        // as-is from license-manager.ts's own baselineTime fallback).
        $baselineTime = $this->licenseState['lastCheckedAt'] === 0
            ? self::nowMs()
            : $this->licenseState['lastCheckedAt'];
        $timeSinceLastSuccess = self::nowMs() - $baselineTime;

        if ($timeSinceLastSuccess >= $this->gracePeriodMs) {
            // Grace period expired — degrade to monitor-only. Logged visibly
            // (warning), never silently, per TODO 321's fix intent.
            $this->licenseState['degraded'] = true;
            $this->licenseState['degradationReason'] = sprintf(
                'License check failed for %dh (grace period: %dh). Reason: %s. SDK degraded to monitor-only mode.',
                (int) round($timeSinceLastSuccess / 3_600_000),
                (int) round($this->gracePeriodMs / 3_600_000),
                $reason,
            );
            $this->log('warning', $this->licenseState['degradationReason']);
        } else {
            $this->log('debug', sprintf(
                'License check failed (%s), %d consecutive failures, %dh grace remaining',
                $reason,
                $this->licenseState['consecutiveFailures'],
                (int) round(($this->gracePeriodMs - $timeSinceLastSuccess) / 3_600_000),
            ));
        }
    }

    /** @return LicenseState */
    public function getLicenseState(): array
    {
        return $this->licenseState;
    }

    /**
     * Check if the SDK should operate in degraded (monitor-only) mode.
     * Degraded mode means: no blocking, no rate limiting, just logging.
     */
    public function isDegraded(): bool
    {
        return $this->licenseState['degraded'];
    }

    /** Check if a specific capability is available in current license state. */
    public function canPerformAction(string $action): bool
    {
        if ($action === 'observe') {
            return true; // Always allowed.
        }
        if ($this->licenseState['degraded']) {
            return false; // Degraded = monitor-only.
        }
        if (!$this->licenseState['valid'] && $this->licenseState['lastCheckedAt'] === 0) {
            // Never validated yet — allow actions during initial grace period.
            return true;
        }

        return $this->licenseState['valid'];
    }

    // ── CV-M4: ML Model Expiry ─────────────────────────────────

    /**
     * Check if the embedded ML model has expired.
     * If expired (>30 days without platform sync), ICL falls back to Tier 1 only.
     */
    public function isModelExpired(): bool
    {
        $age = self::nowMs() - $this->modelState['lastSyncedAt'];
        $this->modelState['expired'] = $age > $this->modelExpiryMs;

        return $this->modelState['expired'];
    }

    /** @return ModelState */
    public function getModelState(): array
    {
        return [...$this->modelState, 'expired' => $this->isModelExpired()];
    }

    /** Manually trigger a model sync (called from the host's init or heartbeat). */
    public function syncModel(string $modelVersion): void
    {
        $this->modelState = [
            'lastSyncedAt' => self::nowMs(),
            'modelVersion' => $modelVersion,
            'expired' => false,
        ];
        $this->log('info', "ML model synced: version={$modelVersion}");
    }

    // ── CV-M7: Anti-Tampering ──────────────────────────────────

    /**
     * Compute HMAC signature over critical SDK code paths.
     * If the SDK distribution has been modified, this hash will differ
     * from the expected value on the platform side.
     */
    public function computeIntegrityHash(): string
    {
        if ($this->integritySecret === null || $this->integritySecret === '') {
            return 'no-integrity-secret';
        }

        // Hash critical module references (class names, method signatures).
        $criticalPaths = implode('|', [
            'DevFortress.observe',
            'DevFortress.isBlocked',
            'LicenseManager.checkLicense',
            'InternalClosedLoopEngine.evaluate',
            'TierGate.checkEventLimit',
        ]);

        return substr(
            hash_hmac('sha256', $criticalPaths . $this->apiKey, $this->integritySecret),
            0,
            16,
        );
    }

    /**
     * Verify that the SDK has not been tampered with.
     * Returns `tampered: true` if the integrity hash doesn't match.
     *
     * @return array{tampered: bool, hash: string}
     */
    public function verifyIntegrity(?string $expectedHash = null): array
    {
        $currentHash = $this->computeIntegrityHash();
        if ($expectedHash === null || $expectedHash === '') {
            return ['tampered' => false, 'hash' => $currentHash];
        }

        return [
            'tampered' => $currentHash !== $expectedHash,
            'hash' => $currentHash,
        ];
    }

    // ── Cleanup ────────────────────────────────────────────────

    /** Reset initialization state. There is no timer to clear (see class doc comment). */
    public function destroy(): void
    {
        $this->initialized = false;
    }

    // ── Logging ────────────────────────────────────────────────

    private function log(string $level, string $message): void
    {
        try {
            $this->logger?->log($level, "[DevFortress:License] {$message}");
        } catch (Throwable) {
            // A failing logger must not reach the host application either.
        }
    }

    /** @param array<string, mixed> $payload */
    private static function encode(array $payload): string
    {
        $encoded = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);

        return $encoded;
    }

    /** @return array<string, mixed> */
    private static function decodeObject(string $body): array
    {
        if ($body === '') {
            return [];
        }
        $decoded = json_decode($body, true);
        if (!is_array($decoded)) {
            return [];
        }

        $result = [];
        foreach ($decoded as $key => $value) {
            if (is_string($key)) {
                $result[$key] = $value;
            }
        }

        return $result;
    }

    private static function nowMs(): int
    {
        return (int) round(microtime(true) * 1000);
    }
}
