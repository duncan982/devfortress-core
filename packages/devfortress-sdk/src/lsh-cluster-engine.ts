/**
 * Open-core stub — the real LSHClusterEngine (MinHash/LSH fingerprint
 * clustering + campaign detection, Invention A2) is proprietary and not
 * part of this build. See open-core-strip.sh Op 14.
 *
 * ingest() always reports campaign: null, so DevFortressCore's observe()
 * never flags a coordinated-campaign signal this build cannot evaluate.
 */

export interface LSHClusterConfig {
  numBands?: number;
  rowsPerBand?: number;
  similarityThreshold?: number;
  campaignMinParticipants?: number;
  explosionGuardMaxClusterSize?: number;
  clusterTtlMs?: number;
}

export interface RequestFingerprint {
  sourceId: string;
  endpoint: string;
  method: string;
  headerSignature: string[];
  bodyHash?: string;
  userAgent?: string;
  timestamp: number;
}

export interface FingerprintCluster {
  id: string;
  members: Set<string>;
  sharedEndpoints: Map<string, number>;
  createdAt: number;
  lastActivity: number;
  isCampaign: boolean;
  explosionGuardTriggered: boolean;
}

export interface CampaignSignature {
  clusterId: string;
  targetEndpoints: string[];
  participantCount: number;
  startTime: number;
  lastSeen: number;
  confidence: number;
  mitigated: boolean;
}

export interface LSHMatchResult {
  sourceId: string;
  clusterId: string | null;
  similarity: number;
  newCluster: boolean;
  explosionGuard: boolean;
  campaign: CampaignSignature | null;
}

export class LSHClusterEngine {
  constructor(_config: LSHClusterConfig = {}) {}

  ingest(fp: RequestFingerprint): LSHMatchResult {
    return {
      sourceId: fp.sourceId,
      clusterId: null,
      similarity: 0,
      newCluster: false,
      explosionGuard: false,
      campaign: null,
    };
  }
}
