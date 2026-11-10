/**
 * S38 — Low-Bandwidth SDK Transport
 *
 * Optimizes event delivery for 2G/3G networks:
 * - pako DEFLATE compression to minimise payload bytes
 * - Minimal payload builder stripping non-essential fields
 * - Connection-aware batching control
 *
 * Author: Duncan Ndungu Ndegwa
 */

import pako from 'pako';

export type ConnectionType = '2g' | '3g' | '4g' | 'wifi' | 'unknown';

export interface LowBandwidthConfig {
  connectionType?: ConnectionType;
  batchSize?: number; // default 10
  batchWindowMs?: number; // default 5000
  targetMaxBytes?: number; // default 200
}

export function compressPayload(payload: object): Uint8Array {
  const json = JSON.stringify(payload);
  return pako.deflate(json);
}

export function decompressPayload(compressed: Uint8Array): object {
  const json = pako.inflate(compressed, { to: 'string' });
  return JSON.parse(json) as object;
}

export function shouldBatch(connectionType: ConnectionType): boolean {
  return connectionType === '2g' || connectionType === '3g';
}

export function buildMinimalPayload(
  event: Record<string, unknown>
): Record<string, unknown> {
  // Strip non-essential fields to minimise payload size
  const { threatType, sourceIp, subjectId, timestamp, severity } = event;
  return {
    t: threatType,
    ip: sourceIp,
    s: subjectId,
    ts: timestamp,
    sv: severity,
  };
}

export function estimatePayloadBytes(payload: object): number {
  return new TextEncoder().encode(JSON.stringify(payload)).length;
}
