/**
 * Alias binding verification helper.
 *
 * Thin HTTP transport for POST /api/aliases/[id]/verify. All binding checks
 * run server-side; nothing is evaluated locally. Retry behaviour matches
 * DevFortressClient: exponential backoff on 5xx and network errors only,
 * never on 4xx.
 */

import axios, { AxiosError } from 'axios';
import { SDK_VERSION } from './version';

const DEFAULT_BASE_URL = 'https://www.devfortress.net';
const DEFAULT_TIMEOUT = 15000;
const DEFAULT_RETRIES = 3;

export type AliasOperationClass =
  | 'read'
  | 'download'
  | 'list'
  | 'write'
  | 'publish'
  | 'message';

/** Observed invocation context, reported from outside the aliased workload. */
export interface AliasVerifyContext {
  requestIp: string;
  geoCountry?: string;
  workloadId?: string;
  deviceFingerprint?: string;
  appBundleId?: string;
  agentToolId?: string;
  /** ISO-8601 timestamp */
  requestTimestamp?: string;
  containerId?: string;
  egressPath?: string;
  processSignature?: string;
  observedOperationClass?: AliasOperationClass;
  observedModelIdentifier?: string;
}

export interface AliasVerifyOptions {
  /** Platform origin, e.g. https://www.devfortress.net. */
  baseUrl?: string;
  timeout?: number;
  retries?: number;
}

export interface AliasBindingViolation {
  type: string;
  aliasId: string;
  expected?: unknown;
  received?: unknown;
  severity: string;
  response: string;
  [key: string]: unknown;
}

export interface AliasVerifyResult {
  /** HTTP status returned by the platform (200, or 403 for a violation / inactive alias). */
  httpStatus: number;
  valid: boolean;
  violations: AliasBindingViolation[];
  note?: string;
  /** Present when the alias is no longer active (e.g. ALIAS_INACTIVE). */
  code?: string;
  state?: string;
  error?: string;
}

export class AliasVerifyError extends Error {
  constructor(
    message: string,
    public readonly httpStatus?: number,
    public readonly body?: unknown
  ) {
    super(message);
    this.name = 'AliasVerifyError';
  }
}

/**
 * Verify an alias's observed context against its recorded binding.
 *
 * Resolves for 200 and 403 responses (the platform's normal verdicts).
 * Throws AliasVerifyError for 400/401 and for 5xx/network failures once
 * retries are exhausted.
 */
export async function verifyAliasBinding(
  aliasId: string,
  aliasKey: string,
  context: AliasVerifyContext,
  options: AliasVerifyOptions = {}
): Promise<AliasVerifyResult> {
  if (!aliasId) throw new Error('verifyAliasBinding: aliasId is required');
  if (!aliasKey) throw new Error('verifyAliasBinding: aliasKey is required');

  const baseUrl = (options.baseUrl || DEFAULT_BASE_URL).replace(/\/+$/, '');
  const retries = options.retries || DEFAULT_RETRIES;
  const url = `${baseUrl}/api/aliases/${encodeURIComponent(aliasId)}/verify`;

  for (let attempt = 1; ; attempt++) {
    try {
      const response = await axios.post(
        url,
        { aliasKey, context },
        {
          timeout: options.timeout || DEFAULT_TIMEOUT,
          headers: {
            'Content-Type': 'application/json',
            'X-DevFortress-SDK-Version': SDK_VERSION,
          },
          // 4xx and 5xx are handled below rather than thrown by axios.
          validateStatus: () => true,
        }
      );
      const status = response.status;
      const data = response.data ?? {};

      if (status === 200 || status === 403) {
        return { httpStatus: status, violations: [], ...data };
      }
      if (status < 500) {
        throw new AliasVerifyError(
          data.error || `Alias verification failed with status ${status}`,
          status,
          data
        );
      }
      if (attempt >= retries) {
        throw new AliasVerifyError(
          data.error || `Alias verification failed with status ${status}`,
          status,
          data
        );
      }
    } catch (error) {
      if (error instanceof AliasVerifyError) {
        // Only 5xx reaches here with retries left; 4xx is final.
        if ((error.httpStatus ?? 500) < 500 || attempt >= retries) throw error;
      } else {
        const axiosError = error as AxiosError;
        if (attempt >= retries) {
          throw new AliasVerifyError(
            `Alias verification request failed: ${axiosError.message}`
          );
        }
      }
    }
    await new Promise(resolve =>
      setTimeout(resolve, Math.pow(2, attempt) * 1000)
    );
  }
}
