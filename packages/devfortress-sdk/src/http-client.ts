import { signedFetchHeaders } from './ingest-signing';
import { PayloadProtectionService } from './payload-protection';

export interface SignedRequestOptions {
  workloadId?: string;
  deviceFingerprint?: string;
  appBundleId?: string;
  agentToolId?: string;
}

/**
 * @deprecated Use the stock client (`DevFortressClient` / `DevFortress`) for
 * ingest. Kept for source compatibility: it now signs like the stock client
 * (key ID, contract v2) and never sends the API key. `projectId` and `pps` are
 * unused. Will be removed in the next major version.
 */
export async function signedPlatformRequest(
  url: string,
  body: object,
  apiKey: string,
  _projectId: string,
  _pps: PayloadProtectionService,
  options?: SignedRequestOptions
): Promise<Response> {
  const rawBody = JSON.stringify(body);
  return fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...signedFetchHeaders(apiKey, 'POST', url, rawBody),
      ...(options?.workloadId && {
        'X-DevFortress-Workload-Id': options.workloadId,
      }),
      ...(options?.deviceFingerprint && {
        'X-DevFortress-Device-Fp': options.deviceFingerprint,
      }),
      ...(options?.appBundleId && {
        'X-DevFortress-App-Bundle': options.appBundleId,
      }),
      ...(options?.agentToolId && {
        'X-DevFortress-Agent-Tool': options.agentToolId,
      }),
    },
    body: rawBody,
  });
}
