/**
 * Shared cross-language webhook signature vectors.
 *
 * The same contracts/webhook-signature-vectors.json is asserted by the Python
 * package's test suite (packages/devfortress-python/tests), so signature
 * parity between the two SDKs is checked against identical inputs.
 */
import fs from 'fs';
import path from 'path';
import { DevFortressCore as DevFortress } from '../src/devfortress';

interface Vector {
  name: string;
  secret: string;
  timestamp: string;
  body: string;
  signature: string;
  now: string;
  expected_valid: boolean;
}

const vectorFile = JSON.parse(
  fs.readFileSync(
    path.resolve(
      __dirname,
      '../../../contracts/webhook-signature-vectors.json'
    ),
    'utf8'
  )
) as { vectors: Vector[] };

describe('webhook signature vectors (shared with the Python SDK)', () => {
  beforeEach(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });
  afterEach(() => jest.restoreAllMocks());

  it('loads a non-trivial vector set', () => {
    expect(vectorFile.vectors.length).toBeGreaterThanOrEqual(10);
  });

  it.each(vectorFile.vectors.map(v => [v.name, v] as const))(
    '%s',
    async (_name, v) => {
      jest.spyOn(Date, 'now').mockReturnValue(new Date(v.now).getTime());
      // Fresh instance per vector: the nonce registry is per-instance state.
      const df = new DevFortress({
        apiKey: 'test-key-vectors',
        appId: 'test-app',
        debug: false,
        tier: 'pro',
        license: { enabled: false },
        telemetry: { enabled: false },
        responseWebhook: {
          url: 'https://example.com/webhook',
          secret: v.secret,
          allowLegacyUnsignedWebhooks: true,
        },
      } as any);
      const result = await df.handleWebhook(v.body, v.signature, v.timestamp);
      expect(result).toBe(v.expected_valid);
    }
  );
});
