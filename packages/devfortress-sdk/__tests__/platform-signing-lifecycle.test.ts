/**
 * Wire-level check over a scripted SDK lifecycle: init, license check,
 * heartbeat, track, flush, blocked-status and the other platform calls. Every
 * outbound request is captured by a stub server; none may carry the API key
 * (header, query string or body), and every one must be signed for the exact
 * method and request target that arrived.
 */
import http from 'http';
import { AddressInfo } from 'net';
import { DevFortressCore } from '../src/devfortress';
import { DevFortressClient } from '../src/client';
import { MLClassifier } from '../src/ml-classifier';
import { signedPlatformRequest } from '../src/http-client';
import { signRequest, deriveKeyId } from '../src/ingest-signing';

const KEY = 'vx_live_lifecycle_test_key_do_not_use';

interface Seen {
  method: string;
  url: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}

function startServer(seen: Seen[]) {
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', c => (body += c));
    req.on('end', () => {
      seen.push({
        method: req.method as string,
        url: req.url as string,
        headers: req.headers,
        body,
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          success: true,
          valid: true,
          tier: 'pro',
          blocked: false,
          testIPs: [],
        })
      );
    });
  });
  return new Promise<{ server: http.Server; base: string }>(resolve =>
    server.listen(0, '127.0.0.1', () =>
      resolve({
        server,
        base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
      })
    )
  );
}

describe('every SDK-to-platform request over a lifecycle', () => {
  const seen: Seen[] = [];
  const webhookSeen: Seen[] = [];
  let platform: http.Server;
  let webhook: http.Server;
  let base: string;
  let webhookBase: string;

  beforeAll(async () => {
    const p = await startServer(seen);
    platform = p.server;
    base = p.base;
    const w = await startServer(webhookSeen);
    webhook = w.server;
    webhookBase = w.base;
  });
  afterAll(async () => {
    await new Promise<void>(r => platform.close(() => r()));
    await new Promise<void>(r => webhook.close(() => r()));
  });

  it('the key never appears on the wire, and every request is signed for what arrived', async () => {
    const df = new DevFortressCore({
      apiKey: KEY,
      appId: 'lifecycle-test',
      endpoint: `${base}/api/events/ingest`,
      responseWebhook: {
        url: `${webhookBase}/hooks/revoke`,
        secret: 'webhook-secret-for-test',
      },
    } as any);

    // init runs a license check in the background; run one explicitly too.
    await df.getLicenseManager()!.checkLicense();
    await (df.getTelemetryManager() as any).sendHeartbeat();
    await df.trackEvent({ eventType: 'custom', ip: '203.0.113.5' });
    await df.flushTelemetryRollup();
    await df.isBlocked('203.0.113.9', { userId: 'u_1' });
    await df.reportActionTaken('evt_1', { actions: ['blocked'] } as any);
    await df.registerTestIPs(['203.0.113.1']);
    await df.getStatus();
    await df.testConnection();
    await df.deliverSessionRevocation({
      sessionId: 's_1',
      reason: 'test',
    });

    const client = new DevFortressClient({
      apiKey: KEY,
      endpoint: `${base}/api/events/ingest`,
    });
    await client.trackEvent({
      eventType: 'custom',
      ip: '203.0.113.6',
      method: 'GET',
      path: '/x',
      severity: 'LOW',
      authPhase: 'pre_auth',
      actionTaken: 'monitored',
      responseLatencyMs: 1,
      clMode: 'external',
    } as any);
    await client.trackEvents([
      {
        eventType: 'custom',
        ip: '203.0.113.7',
        method: 'GET',
        path: '/y',
        severity: 'LOW',
        authPhase: 'pre_auth',
        actionTaken: 'monitored',
        responseLatencyMs: 1,
        clMode: 'external',
      } as any,
    ]);

    const classifier = new MLClassifier({
      platformEndpoint: base,
      apiKey: KEY,
    } as any);
    await (classifier as any).classifyPlatform(
      { eventType: 'custom', ip: '203.0.113.5', method: 'GET', path: '/x' },
      Date.now()
    );

    await signedPlatformRequest(
      `${base}/api/events/ingest`,
      { eventType: 'custom' },
      KEY,
      'proj',
      {} as any
    );

    (df as any).destroy?.();
    (df as any).shutdown?.();

    // Coverage: each platform call in the lifecycle actually happened.
    const called = seen.map(r => `${r.method} ${r.url.split('?')[0]}`);
    for (const expected of [
      'POST /api/sdk/license-check',
      'POST /api/sdk/heartbeat',
      'POST /api/events/ingest',
      'GET /api/events/blocked',
      'POST /api/events/actions/confirm',
      'POST /api/events/test-ips',
      'GET /api/events/health',
      'POST /api/ml/classify',
    ]) {
      expect(called).toContain(expected);
    }
    expect(seen.length).toBeGreaterThanOrEqual(12);

    const nonces = new Set<string>();
    for (const r of seen) {
      // The key appears nowhere: no header value, no header name carrying it,
      // no query string, no body.
      const carriesKey =
        Object.values(r.headers).some(v => String(v).includes(KEY)) ||
        r.url.includes(KEY) ||
        r.body.includes(KEY);
      expect(carriesKey).toBe(false);
      expect(r.headers['x-devfortress-key']).toBeUndefined();
      expect(r.headers['x-api-key']).toBeUndefined();
      expect(r.headers['authorization']).toBeUndefined();

      // Signed for exactly the method, target and body that arrived.
      expect(r.headers['x-devfortress-key-id']).toBe(deriveKeyId(KEY));
      expect(r.headers['x-devfortress-signature-version']).toBe('2');
      const expected = signRequest(
        KEY,
        r.method,
        r.url,
        r.body,
        r.headers['x-devfortress-timestamp'] as string,
        r.headers['x-devfortress-nonce'] as string
      );
      expect(r.headers['x-devfortress-signature']).toBe(
        expected['X-DevFortress-Signature']
      );
      expect(r.headers['x-devfortress-payload-hash']).toBe(
        expected['X-DevFortress-Payload-Hash']
      );
      nonces.add(r.headers['x-devfortress-nonce'] as string);
    }
    // A fresh nonce per attempt.
    expect(nonces.size).toBe(seen.length);

    // The customer's webhook host receives nothing that identifies the
    // project: no key, no key ID.
    expect(webhookSeen.length).toBeGreaterThanOrEqual(1);
    for (const r of webhookSeen) {
      expect(JSON.stringify(r.headers)).not.toContain(KEY);
      expect(JSON.stringify(r.headers)).not.toContain(deriveKeyId(KEY));
      expect(r.body).not.toContain(KEY);
      expect(r.headers['x-devfortress-key']).toBeUndefined();
      expect(r.headers['x-devfortress-key-id']).toBeUndefined();
    }
  }, 30000);
});
