import crypto from 'crypto';
import type { AxiosInstance, InternalAxiosRequestConfig } from 'axios';

/**
 * Request integrity headers for every SDK-to-platform call (signature
 * contract v2).
 *
 * Canonical string: `${METHOD}.${requestTarget}.${timestamp}.${nonce}.${payloadHash}`
 * where METHOD is the uppercase HTTP method, requestTarget is the URL path plus
 * `?query` exactly as sent (no host, no re-encoding), and payloadHash is the
 * lowercase hex SHA-256 of the exact body bytes (the empty string for a
 * request without a body). The signature is the lowercase hex HMAC-SHA256 of
 * that string, keyed with the project API key.
 * Contract + shared vectors: contracts/ingest-signature-*.
 *
 * The API key never travels on a signed request. `X-DevFortress-Key-Id` is a
 * non-secret identifier derived from the key (first 32 hex characters of its
 * SHA-256), and the platform verifies the HMAC with the key it has stored.
 */
export const SIGNATURE_VERSION = '2';

export interface RequestSignatureHeaders {
  'X-DevFortress-Key-Id': string;
  'X-DevFortress-Signature-Version': string;
  'X-DevFortress-Nonce': string;
  'X-DevFortress-Timestamp': string;
  'X-DevFortress-Payload-Hash': string;
  'X-DevFortress-Signature': string;
}

/** Every header name that could carry the API key. Never sent on a signed request. */
const KEY_CARRIER_HEADERS = ['X-DevFortress-Key', 'X-API-Key', 'Authorization'];

export function deriveKeyId(apiKey: string): string {
  return crypto
    .createHash('sha256')
    .update(apiKey, 'utf8')
    .digest('hex')
    .slice(0, 32);
}

/** Path plus `?query` of an absolute URL, as it goes on the request line. */
export function requestTargetOf(url: string): string {
  const u = new URL(url);
  return u.pathname + u.search;
}

export function signRequest(
  apiKey: string,
  method: string,
  requestTarget: string,
  rawBody: string,
  timestamp: string = String(Date.now()),
  nonce: string = crypto.randomUUID()
): RequestSignatureHeaders {
  const payloadHash = crypto
    .createHash('sha256')
    .update(rawBody, 'utf8')
    .digest('hex');
  const signature = crypto
    .createHmac('sha256', apiKey)
    .update(
      `${method.toUpperCase()}.${requestTarget}.${timestamp}.${nonce}.${payloadHash}`,
      'utf8'
    )
    .digest('hex');
  return {
    'X-DevFortress-Key-Id': deriveKeyId(apiKey),
    'X-DevFortress-Signature-Version': SIGNATURE_VERSION,
    'X-DevFortress-Nonce': nonce,
    'X-DevFortress-Timestamp': timestamp,
    'X-DevFortress-Payload-Hash': payloadHash,
    'X-DevFortress-Signature': signature,
  };
}

/**
 * Headers for a `fetch` call: sign `method` + the URL's path and query + the
 * body text. Call once per attempt so every retry carries a fresh nonce and
 * timestamp. Spread the result into the request headers.
 */
export function signedFetchHeaders(
  apiKey: string,
  method: string,
  url: string,
  rawBody = ''
): RequestSignatureHeaders {
  return signRequest(apiKey, method, requestTargetOf(url), rawBody);
}

/**
 * Sign every request sent through an axios instance. The interceptor runs once
 * per attempt, so retries carry a fresh nonce and timestamp.
 */
export function attachPlatformSigning(
  instance: AxiosInstance,
  apiKey: string
): void {
  // Minimal axios stand-ins (tests, custom adapters) may have no interceptors.
  if (!instance.interceptors?.request) return;
  instance.interceptors.request.use((config: InternalAxiosRequestConfig) => {
    const raw =
      config.data == null
        ? ''
        : typeof config.data === 'string'
          ? config.data
          : JSON.stringify(config.data);
    if (raw !== '') config.data = raw;
    // Signed requests identify the project by key ID: the key itself is
    // never sent.
    for (const name of KEY_CARRIER_HEADERS) config.headers.delete(name);
    const method = (config.method ?? 'get').toUpperCase();
    const target = requestTargetOf(instance.getUri(config));
    const headers = signRequest(apiKey, method, target, raw);
    for (const [k, v] of Object.entries(headers)) config.headers.set(k, v);
    return config;
  });
}
