/**
 * License-check and heartbeat must resolve against the platform base URL,
 * not the full ingest URL.
 */

import { DevFortressCore } from '../src/devfortress';
import { SDK_VERSION } from '../src/version';

jest.mock('axios', () => {
  const inst = {
    post: jest.fn().mockResolvedValue({ data: { success: true } }),
    get: jest.fn().mockResolvedValue({ data: { blocked: false } }),
    patch: jest.fn().mockResolvedValue({ data: { success: true } }),
  };
  return {
    create: jest.fn(() => inst),
    __mockInstance: inst,
    isAxiosError: (e: unknown) =>
      e && typeof e === 'object' && 'isAxiosError' in e,
  };
});

describe('license-check / heartbeat URL', () => {
  const realFetch = globalThis.fetch;
  let fetchMock: jest.Mock;

  beforeEach(() => {
    jest.useFakeTimers();
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    fetchMock = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ tier: 'pro' }),
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = realFetch;
    jest.useRealTimers();
    jest.restoreAllMocks();
  });

  it('calls license-check and heartbeat on the base URL with the real version', async () => {
    const df = new DevFortressCore({
      apiKey: 'test-key',
      appId: 'test-app',
      endpoint: 'https://platform.example.com/api/events/ingest',
      telemetry: { heartbeatIntervalMs: 60_000 },
    } as never);

    await jest.advanceTimersByTimeAsync(10_000);

    const urls = fetchMock.mock.calls.map(c => c[0] as string);
    expect(urls).toContain(
      'https://platform.example.com/api/sdk/license-check'
    );
    expect(urls).toContain('https://platform.example.com/api/sdk/heartbeat');
    expect(
      urls.some(u => u.includes('/ingest/') || u.includes('/events/api/'))
    ).toBe(false);

    const licenseCall = fetchMock.mock.calls.find(c =>
      (c[0] as string).endsWith('/api/sdk/license-check')
    )!;
    expect(JSON.parse(licenseCall[1].body).sdkVersion).toBe(SDK_VERSION);
    expect(SDK_VERSION).toBe(require('../package.json').version);

    df.destroy();
  });
});
