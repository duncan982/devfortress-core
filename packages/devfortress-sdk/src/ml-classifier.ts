/**
 * Open-core stub — the real MLClassifier's embedded ONNX threat-classifier
 * model/inference code is proprietary and not part of this build. See
 * open-core-strip.sh Op 14.
 *
 * Mirrors the real module's public interface exactly, so devfortress.ts
 * compiles and runs unmodified. embeddedAvailable is always false (no
 * proprietary model shipped), so classify() always takes the real class's
 * own "platform or heuristic" fallback branch — this stub keeps the
 * platform-relay path for real (calling the hosted DevFortress platform's
 * /api/ml/classify is not itself proprietary; only the embedded model is),
 * signed via signedFetchHeaders exactly like the real class, so the open-
 * core build keeps the "API key never on the wire, every request signed"
 * guarantee even for this call. With no platformEndpoint/apiKey configured,
 * classify() falls back to a zero-confidence "no signal" result — the same
 * neutral result the real class's own classifyHeuristic ultimately
 * degrades to failure/timeout with, so Tier 2 ML scoring contributes
 * nothing rather than fabricating a severity.
 */
import { signedFetchHeaders } from './ingest-signing';

export interface EventFeatures {
  eventType: string;
  ip: string;
  method: string;
  path: string;
  statusCode?: number;
  responseLatencyMs?: number;
  hourOfDay?: number;
  requestsInWindow?: number;
  failedAuthsInWindow?: number;
  uniquePathsInWindow?: number;
  authPhase?: 'pre_auth' | 'post_auth';
  isAgent?: boolean;
}

export interface ClassificationResult {
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: number;
  modelSource: 'embedded' | 'platform';
  rawScores?: number[];
  modelVersion?: string;
  inferenceLatencyMs?: number;
}

export interface MLClassifierConfig {
  modelPath?: string;
  platformEndpoint?: string;
  apiKey?: string;
  platformTimeoutMs?: number;
  preferPlatform?: boolean;
  minConfidence?: number;
}

export function extractFeatures(_features: EventFeatures): Float32Array {
  return new Float32Array(0);
}

function neutralResult(startMs: number): ClassificationResult {
  return {
    severity: 'LOW',
    confidence: 0,
    modelSource: 'embedded',
    modelVersion: 'open-core-stub',
    inferenceLatencyMs: Date.now() - startMs,
  };
}

export class MLClassifier {
  private config: MLClassifierConfig;

  constructor(config: MLClassifierConfig = {}) {
    this.config = config;
  }

  async classify(features: EventFeatures): Promise<ClassificationResult> {
    const startMs = Date.now();
    if (this.config.platformEndpoint && this.config.apiKey) {
      return this.classifyPlatform(features, startMs);
    }
    return neutralResult(startMs);
  }

  private async classifyPlatform(
    features: EventFeatures,
    startMs: number
  ): Promise<ClassificationResult> {
    try {
      const url = `${this.config.platformEndpoint}/api/ml/classify`;
      const body = JSON.stringify({
        features: [],
        eventType: features.eventType,
        ip: features.ip,
        method: features.method,
        path: features.path,
      });
      const controller = new AbortController();
      const timeout = setTimeout(
        () => controller.abort(),
        this.config.platformTimeoutMs ?? 5000
      );
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...signedFetchHeaders(this.config.apiKey!, 'POST', url, body),
        },
        body,
        signal: controller.signal,
      });
      clearTimeout(timeout);

      if (!response.ok) {
        return neutralResult(startMs);
      }

      const data = (await response.json()) as {
        severity?: string;
        confidence?: number;
        rawScores?: number[];
        modelVersion?: string;
      };

      return {
        severity:
          (data.severity as ClassificationResult['severity']) ?? 'MEDIUM',
        confidence: data.confidence ?? 0.5,
        modelSource: 'platform',
        rawScores: data.rawScores,
        modelVersion: data.modelVersion ?? 'platform',
        inferenceLatencyMs: Date.now() - startMs,
      };
    } catch {
      return neutralResult(startMs);
    }
  }

  isEmbeddedAvailable(): boolean {
    return false;
  }

  getModelVersion(): string {
    return 'open-core-stub';
  }

  getStatus(): {
    initialized: boolean;
    embeddedAvailable: boolean;
    modelVersion: string;
    platformConfigured: boolean;
  } {
    return {
      initialized: true,
      embeddedAvailable: false,
      modelVersion: 'open-core-stub',
      platformConfigured: !!(
        this.config.platformEndpoint && this.config.apiKey
      ),
    };
  }
}
