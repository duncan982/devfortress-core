<?php

declare(strict_types=1);

return [
    /*
     | Turn event reporting off without removing the middleware.
     */
    'enabled' => env('DEVFORTRESS_ENABLED', true),

    /*
     | Your project API key. It is used to sign requests and is never sent.
     */
    'api_key' => env('DEVFORTRESS_API_KEY'),

    /*
     | The platform's ingest URL.
     */
    'endpoint' => env('DEVFORTRESS_ENDPOINT', 'https://www.devfortress.net/api/events/ingest'),

    /*
     | Seconds to wait for the platform, and how many attempts a delivery gets
     | (network errors and 5xx responses are retried, 4xx responses are not).
     */
    'timeout' => (float) env('DEVFORTRESS_TIMEOUT', 15),
    'retries' => (int) env('DEVFORTRESS_RETRIES', 3),

    /*
     | Sent with every event. Both fall back to the app name and environment.
     */
    'app_id' => env('DEVFORTRESS_APP_ID'),
    'environment' => env('DEVFORTRESS_ENVIRONMENT'),

    /*
     | "standard", or "strict" to hash IP addresses and drop user agents.
     */
    'privacy' => env('DEVFORTRESS_PRIVACY', 'standard'),

    /*
     | Closed-loop mode: "external" (default, unchanged behavior — no
     | pre-response gate), "internal" (local-only InternalClosedLoopEngine
     | gate, no platform round-trip), or "hybrid" (internal-first, with a
     | circuit-breaker-gated external enrichment leg). See
     | DevFortress\Sdk\InternalClosedLoopEngine and the middleware's
     | internalGate().
     */
    'mode' => env('DEVFORTRESS_CL_MODE', 'external'),

    /*
     | Secret for verifying inbound DevFortress webhooks (see WebhookVerifier in
     | devfortress/devfortress-sdk). Read it here, not with env() elsewhere: env() returns
     | null outside config files once the configuration is cached.
     */
    'webhook_secret' => env('DEVFORTRESS_WEBHOOK_SECRET'),

    /*
     | Requests whose path starts with one of these are never reported.
     */
    'exclude_paths' => ['/health', '/up'],

    /*
     | Log channel for delivery failures. Null uses the default channel.
     */
    'log_channel' => env('DEVFORTRESS_LOG_CHANNEL'),
];
