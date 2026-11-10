/**
 * S14 — Core Class Tests: Retry Logic, HMAC Webhook, failClosed, isBlocked
 *
 * Supplements the existing devfortress-v4.test.ts with coverage
 * for the retry mechanism, HMAC signature verification, and
 * failClosed configuration option.
 */

import { DevFortressCore as DevFortress } from '../src/devfortress';
import type { DevFortressConfig } from '../src/types';
import crypto from 'crypto';

// ── Axios Mock Setup (same pattern as devfortress-v4.test.ts) ──

jest.mock('axios', () => {
  const inst = {
    post: jest.fn().mockResolvedValue({
      data: {
        success: true,
        eventId: 'evt_mock',
        flagged: false,
        confidence: 0.1,
      },
    }),
    get: jest.fn().mockResolvedValue({
      data: { blocked: false },
    }),
    patch: jest.fn().mockResolvedValue({ data: { success: true } }),
  };

  return {
    create: jest.fn(() => inst),
    __mockInstance: inst,
    isAxiosError: (e: unknown) =>
      e && typeof e === 'object' && 'isAxiosError' in e,
  };
});

const mockInstance = require('axios').__mockInstance as {
  post: jest.Mock;
  get: jest.Mock;
  patch: jest.Mock;
};

beforeAll(() => {
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});
});

afterAll(() => {
  jest.restoreAllMocks();
});

beforeEach(() => {
  mockInstance.post.mockReset().mockResolvedValue({
    data: {
      success: true,
      eventId: 'evt_test',
      flagged: false,
      confidence: 0.1,
    },
  });
  mockInstance.get.mockReset().mockResolvedValue({
    data: { blocked: false },
  });
  mockInstance.patch.mockReset().mockResolvedValue({ data: { success: true } });
});

/** Base config with license + telemetry disabled to avoid background timers */
function baseConfig(
  overrides: Partial<DevFortressConfig> = {}
): DevFortressConfig {
  return {
    apiKey: 'test-key-retry',
    appId: 'test-app',
    debug: false,
    license: { enabled: false },
    telemetry: { enabled: false },
    ...overrides,
  };
}

function mockReq(ip = '192.168.1.100', path = '/api/test') {
  return {
    method: 'GET',
    url: path,
    headers: {
      'x-forwarded-for': ip,
      'user-agent': 'TestAgent/1.0',
    },
  };
}

// ── Retry Logic Tests ────────────────────────────────────────

describe('DevFortress — Retry Logic', () => {
  it('should retry on 5xx server error and succeed on second attempt', async () => {
    // Use fake timers but keep setImmediate real so jest.setup.js afterEach
    // (which uses setImmediate) doesn't hang.
    jest.useFakeTimers({ doNotFake: ['setImmediate', 'nextTick'] });

    try {
      const serverError = new Error('Server Error') as Error & {
        response: { status: number };
        isAxiosError: boolean;
      };
      serverError.response = { status: 502 };
      serverError.isAxiosError = true;

      // First call fails with 502, second succeeds
      mockInstance.post
        .mockRejectedValueOnce(serverError)
        .mockResolvedValueOnce({
          data: {
            success: true,
            eventId: 'evt_retry',
            flagged: false,
            confidence: 0.05,
          },
        });

      const df = new DevFortress(baseConfig({ tier: 'pro', retries: 3 }));

      // Option B (2026-08-27): external mode now gates clean/first-time
      // traffic to a non-relay rollup path (see devfortress.ts's
      // observeExternal()) — a plain first-time request from a fresh IP no
      // longer reaches sendWithRetry()/axios at all. Use a request whose
      // path matches a known attack pattern (matchesKnownAttackPattern) so
      // this test still exercises what it's meant to: retry behavior on a
      // relay that actually happens.
      const observePromise = df.observe(
        mockReq('8.8.8.8', '/api/test?id=1 OR 1=1')
      );

      // Advance through the exponential backoff: Math.pow(2,1)*1000 = 2000ms
      await jest.advanceTimersByTimeAsync(3000);

      const result = await observePromise;
      void result;

      // Should have retried (at least 2 calls to post)
      expect(mockInstance.post.mock.calls.length).toBeGreaterThanOrEqual(2);
    } finally {
      // In a try/finally so a failed assertion above can't leave fake
      // timers stuck on for the rest of this file's later tests.
      jest.useRealTimers();
    }
  }, 15_000);

  it('should not retry on 4xx client error', async () => {
    const clientError = new Error('Bad Request') as Error & {
      response: { status: number };
      isAxiosError: boolean;
    };
    clientError.response = { status: 400 };
    clientError.isAxiosError = true;

    mockInstance.post.mockRejectedValue(clientError);

    const df = new DevFortress(baseConfig({ tier: 'pro', retries: 3 }));

    // Same Option B note as above — use a relay-triggering path.
    const result = await df.observe(
      mockReq('8.8.8.8', '/api/test?id=1 OR 1=1')
    );
    void result;

    // Should only call once (no retry on 4xx)
    expect(mockInstance.post).toHaveBeenCalledTimes(1);
  });
});

// ── HMAC Webhook Verification ───────────────────────────────

describe('DevFortress — HMAC Webhook Verification', () => {
  const webhookSecret = 'whsec_test_secret_key_12345';

  function signPayload(
    body: string,
    secret: string,
    timestamp: string
  ): string {
    const signatureInput = `${timestamp}.${body}`;
    return crypto
      .createHmac('sha256', secret)
      .update(signatureInput)
      .digest('hex');
  }

  it('should accept a valid HMAC signature', async () => {
    const df = new DevFortress(
      baseConfig({
        tier: 'pro',
        responseWebhook: {
          url: 'https://example.com/webhook',
          secret: webhookSecret,
        },
      })
    );

    const timestamp = new Date().toISOString();
    const body = JSON.stringify({
      event_id: 'evt_123',
      threat_type: 'brute_force',
      severity: 'high',
      confidence: 0.95,
      composite_score: 85,
      ip: '10.0.0.1',
      identity: { user_id: 'user_abc', session_id: 'sess_abc' },
      geo: {},
      endpoint: '/api/login',
      method: 'POST',
      timestamp: timestamp,
      nonce: 'a1b2c3d4e5f60718293a4b5c6d7e8f90',
    });
    const signature = signPayload(body, webhookSecret, timestamp);

    const result = await df.handleWebhook(body, signature, timestamp);
    expect(result).toBe(true);
  });

  it('should reject an invalid HMAC signature', async () => {
    const df = new DevFortress(
      baseConfig({
        tier: 'pro',
        responseWebhook: {
          url: 'https://example.com/webhook',
          secret: webhookSecret,
        },
      })
    );

    const timestamp = new Date().toISOString();
    const body = JSON.stringify({ event_id: 'evt_456', action: 'blocked' });
    const wrongSignature =
      'deadbeefcafe1234567890abcdef1234567890abcdef1234567890abcdef1234';

    const result = await df.handleWebhook(body, wrongSignature, timestamp);
    expect(result).toBe(false);
  });

  it('should reject expired webhook timestamp', async () => {
    const df = new DevFortress(
      baseConfig({
        tier: 'pro',
        responseWebhook: {
          url: 'https://example.com/webhook',
          secret: webhookSecret,
        },
      })
    );

    // 10 minutes ago (beyond 5-minute max age)
    const oldTimestamp = new Date(Date.now() - 600_000).toISOString();
    const body = JSON.stringify({ event_id: 'evt_789' });
    const signature = signPayload(body, webhookSecret, oldTimestamp);

    const result = await df.handleWebhook(body, signature, oldTimestamp);
    expect(result).toBe(false);
  });

  it('should reject webhook when no secret is configured', async () => {
    const df = new DevFortress(baseConfig({ tier: 'pro' }));

    const result = await df.handleWebhook('{}', 'sig', '12345');
    expect(result).toBe(false);
  });
});

// ── failClosed Configuration ─────────────────────────────────

describe('DevFortress — failClosed', () => {
  it('should fail open by default when isBlocked check errors', async () => {
    mockInstance.get.mockRejectedValue(new Error('Network error'));

    const df = new DevFortress(baseConfig({ tier: 'pro' }));

    const blocked = await df.isBlocked('203.0.113.1');
    expect(blocked).toBe(false); // fail-open = not blocked
  });

  it('should fail closed when failClosed is true and isBlocked check errors', async () => {
    mockInstance.get.mockRejectedValue(new Error('Network error'));

    const df = new DevFortress(baseConfig({ tier: 'pro', failClosed: true }));

    const blocked = await df.isBlocked('203.0.113.1');
    expect(blocked).toBe(true); // fail-closed = blocked
  });
});

// ── isBlocked — Private IP Skip ──────────────────────────────

describe('DevFortress — isBlocked Private IP Skip', () => {
  it('should never block loopback IPv4', async () => {
    const df = new DevFortress(baseConfig({ tier: 'pro' }));
    expect(await df.isBlocked('127.0.0.1')).toBe(false);
  });

  it('should never block private 10.x.x.x', async () => {
    const df = new DevFortress(baseConfig({ tier: 'pro' }));
    expect(await df.isBlocked('10.0.0.1')).toBe(false);
  });

  it('should never block IPv6 loopback', async () => {
    const df = new DevFortress(baseConfig({ tier: 'pro' }));
    expect(await df.isBlocked('::1')).toBe(false);
  });

  it('should never block fe80:: link-local', async () => {
    const df = new DevFortress(baseConfig({ tier: 'pro' }));
    expect(await df.isBlocked('fe80::1')).toBe(false);
  });

  it('should check public IPs against platform', async () => {
    mockInstance.get.mockResolvedValue({ data: { blocked: true } });

    const df = new DevFortress(baseConfig({ tier: 'pro' }));

    const blocked = await df.isBlocked('203.0.113.5');
    expect(blocked).toBe(true);
    expect(mockInstance.get).toHaveBeenCalled();
  });
});

// ── Observe — Quota Enforcement ──────────────────────────────

describe('DevFortress — Observe Quota Enforcement', () => {
  it('should return null when daily event limit exhausted', async () => {
    const df = new DevFortress(baseConfig({ tier: 'starter' }));

    // Exhaust event limit
    for (let i = 0; i < 10_000; i++) {
      df.getTierGate().recordEvent();
    }

    const result = await df.observe(mockReq());
    expect(result).toBeNull();
  });

  it('should return null when monthly quota exhausted', async () => {
    const df = new DevFortress(baseConfig({ tier: 'starter' }));

    // Exhaust monthly quota
    for (let i = 0; i < 5_001; i++) {
      df.getTierGate().recordMonthlyEvent();
    }

    const result = await df.observe(mockReq());
    expect(result).toBeNull();
  });
});

// ── Internal Mode — No Platform Calls ────────────────────────

describe('DevFortress — Internal Mode Isolation', () => {
  it('should not make any external API calls in internal mode', async () => {
    const df = new DevFortress(
      baseConfig({ tier: 'enterprise', mode: 'internal' })
    );

    await df.observe(mockReq('8.8.8.8'));
    await df.isBlocked('8.8.8.8');

    // In internal mode, no external calls should be made for observe
    // (isBlocked skips external call since mode is internal)
    const externalGetCalls = mockInstance.get.mock.calls.length;
    expect(externalGetCalls).toBe(0);
  });
});
