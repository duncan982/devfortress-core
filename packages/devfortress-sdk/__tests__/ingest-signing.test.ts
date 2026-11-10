/**
 * Ingest request signing: shared cross-language vectors, plus a wire-level
 * check that the stock clients sign every attempt with a fresh nonce.
 */
import fs from 'fs';
import path from 'path';
import http from 'http';
import { AddressInfo } from 'net';
import { signRequest, deriveKeyId } from '../src/ingest-signing';
import { DevFortressCore } from '../src/devfortress';
import { DevFortressClient } from '../src/client';

interface Vector {
  name: string;
  verify_key: string;
  body: string;
  headers: {
    nonce: string | null;
    timestamp: string | null;
    payload_hash: string | null;
    signature: string | null;
    version: string | null;
  };
  now_ms: number;
  expected: string;
  sign_input?: SignInput;
}

interface SignInput {
  api_key: string;
  method: string;
  request_target: string;
  timestamp: string;
  nonce: string;
  body: string;
}

const sign = (i: SignInput) =>
  signRequest(
    i.api_key,
    i.method,
    i.request_target,
    i.body,
    i.timestamp,
    i.nonce
  );

const file = JSON.parse(
  fs.readFileSync(
    path.resolve(__dirname, '../../../contracts/ingest-signature-vectors.json'),
    'utf8'
  )
) as {
  vectors: Vector[];
  key_id_derivation: { vectors: { api_key: string; key_id: string }[] };
  signed_path_vectors: {
    name: string;
    headers: { key_id: string };
    sign_input?: SignInput;
  }[];
};

describe('ingest signature vectors (shared with the Python SDK)', () => {
  const signing = file.vectors.filter(
    v => v.sign_input && ['valid', 'expired'].includes(v.expected)
  );

  it('has signing vectors', () => {
    expect(signing.length).toBeGreaterThanOrEqual(3);
  });

  for (const v of signing) {
    it(`signs ${v.name} byte-for-byte`, () => {
      const h = sign(v.sign_input!);
      expect(h['X-DevFortress-Payload-Hash']).toBe(
        v.headers.payload_hash?.toLowerCase()
      );
      expect(h['X-DevFortress-Signature']).toBe(
        v.headers.signature?.toLowerCase()
      );
      expect(h['X-DevFortress-Nonce']).toBe(v.headers.nonce);
      expect(h['X-DevFortress-Timestamp']).toBe(v.headers.timestamp);
      expect(h['X-DevFortress-Signature-Version']).toBe('2');
    });
  }

  for (const v of file.key_id_derivation.vectors) {
    it(`derives key ID ${v.key_id} from the key`, () => {
      expect(deriveKeyId(v.api_key)).toBe(v.key_id);
    });
  }

  for (const v of file.signed_path_vectors.filter(x => x.sign_input)) {
    it(`signed-path vector ${v.name}: key ID and signature match byte-for-byte`, () => {
      const h = sign(v.sign_input!);
      expect(h['X-DevFortress-Key-Id']).toBe(v.headers.key_id);
      expect(h['X-DevFortress-Signature']).toBe((v.headers as any).signature);
    });
  }

  it('negative vectors do not match what the signer produces', () => {
    // The same signature must not verify on a different path, method or
    // query: re-signing the request the server actually received differs.
    for (const v of file.vectors.filter(v =>
      [
        'tampered_body',
        'wrong_key',
        'different_path',
        'different_method',
        'changed_query',
        'prefix_stripped',
      ].includes(v.name)
    )) {
      const h = signRequest(
        v.verify_key,
        (v as any).method,
        (v as any).request_target,
        v.body,
        v.headers.timestamp!,
        v.headers.nonce!
      );
      expect(h['X-DevFortress-Signature']).not.toBe(v.headers.signature);
    }
  });
});

describe('stock client signs every attempt', () => {
  let server: http.Server;
  let url: string;
  const seen: {
    headers: http.IncomingHttpHeaders;
    body: string;
    method: string;
    url: string;
  }[] = [];
  let failFirst = 0;

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      let body = '';
      req.on('data', c => (body += c));
      req.on('end', () => {
        seen.push({
          headers: req.headers,
          body,
          method: req.method as string,
          url: req.url as string,
        });
        const fail = failFirst > 0;
        if (fail) failFirst--;
        res.writeHead(fail ? 500 : 200, { 'Content-Type': 'application/json' });
        res.end('{"success":true}');
      });
    });
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api/events/ingest`;
  });
  afterAll(() => new Promise<void>(r => server.close(() => r())));
  beforeEach(() => {
    seen.length = 0;
    failFirst = 0;
  });

  const KEY = 'vx_live_test_vector_key_do_not_use';
  const event = {
    eventType: 'custom',
    ip: '203.0.113.5',
    method: 'GET',
    path: '/x',
    severity: 'LOW' as const,
    authPhase: 'pre_auth' as const,
    actionTaken: 'monitored' as const,
    responseLatencyMs: 1,
    clMode: 'external',
  };

  it('single event carries a valid signature over the exact body sent', async () => {
    const c = new DevFortressClient({ apiKey: KEY, endpoint: url });
    await c.trackEvent(event as any);
    expect(seen).toHaveLength(1);
    const h = seen[0].headers;
    const expected = signRequest(
      KEY,
      seen[0].method,
      seen[0].url,
      seen[0].body,
      h['x-devfortress-timestamp'] as string,
      h['x-devfortress-nonce'] as string
    );
    expect(h['x-devfortress-signature']).toBe(
      expected['X-DevFortress-Signature']
    );
    expect(h['x-devfortress-payload-hash']).toBe(
      expected['X-DevFortress-Payload-Hash']
    );
    expect(h['x-devfortress-nonce']).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('batch is signed too', async () => {
    const c = new DevFortressClient({ apiKey: KEY, endpoint: url });
    await c.trackEvents([event as any, event as any]);
    const h = seen[0].headers;
    const expected = signRequest(
      KEY,
      seen[0].method,
      seen[0].url,
      seen[0].body,
      h['x-devfortress-timestamp'] as string,
      h['x-devfortress-nonce'] as string
    );
    expect(h['x-devfortress-signature']).toBe(
      expected['X-DevFortress-Signature']
    );
  });

  it('a retried request gets a fresh nonce and its own valid signature', async () => {
    failFirst = 1;
    const c = new DevFortressClient({ apiKey: KEY, endpoint: url, retries: 2 });
    await c.trackEvent(event as any);
    expect(seen).toHaveLength(2);
    const [a, b] = seen.map(s => s.headers);
    expect(a['x-devfortress-nonce']).not.toBe(b['x-devfortress-nonce']);
    for (const s of seen) {
      const e = signRequest(
        KEY,
        s.method,
        s.url,
        s.body,
        s.headers['x-devfortress-timestamp'] as string,
        s.headers['x-devfortress-nonce'] as string
      );
      expect(s.headers['x-devfortress-signature']).toBe(
        e['X-DevFortress-Signature']
      );
    }
  }, 15000);

  const carriesKey = (r: {
    headers: http.IncomingHttpHeaders;
    body: string;
    url: string;
  }) =>
    Object.values(r.headers).some(v => String(v).includes(KEY)) ||
    r.body.includes(KEY) ||
    r.url.includes(KEY);

  it('the stock client sends a key ID and never the key', async () => {
    const c = new DevFortressClient({ apiKey: KEY, endpoint: url });
    await c.trackEvent(event as any);
    await c.trackEvents([event as any]);
    expect(seen).toHaveLength(2);
    for (const r of seen) {
      expect(carriesKey(r)).toBe(false);
      expect(r.headers['x-devfortress-key']).toBeUndefined();
      expect(r.headers['x-devfortress-key-id']).toBe(deriveKeyId(KEY));
    }
  });

  it('a retry carries a key ID and never the key either', async () => {
    failFirst = 1;
    const c = new DevFortressClient({ apiKey: KEY, endpoint: url, retries: 2 });
    await c.trackEvent(event as any);
    expect(seen).toHaveLength(2);
    expect(seen.some(carriesKey)).toBe(false);
  }, 15000);

  it('the full SDK ingest call sends a key ID and never the key', async () => {
    const df = new DevFortressCore({
      apiKey: KEY,
      appId: 'wire-test',
      endpoint: url,
      license: { enabled: false },
      telemetry: { enabled: false },
    } as any);
    await df.trackEvent({ eventType: 'custom', ip: '203.0.113.5' });
    const ingest = seen.filter(r => r.body.includes('203.0.113.5'));
    expect(ingest.length).toBeGreaterThanOrEqual(1);
    for (const r of ingest) {
      expect(carriesKey(r)).toBe(false);
      expect(r.headers['x-devfortress-key']).toBeUndefined();
      expect(r.headers['x-devfortress-key-id']).toBe(deriveKeyId(KEY));
    }
    await (df as any).shutdown?.();
  });
});
