// packages/devfortress-sdk/src/specialization/plugin-interface.ts

import type { SpecializationModeId } from './manifest';

export interface DetectionContext {
  ip: string;
  subjectId: string;
  endpoint: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
  timestamp: number;
}

export interface DetectionResult {
  detected: boolean;
  threatType: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: number; // 0–100
  details: string;
  suggestedAction: 'log' | 'alert' | 'block' | 'challenge';
}

export interface SpecializationPlugin {
  modeId: SpecializationModeId;
  version: string;
  detect(ctx: DetectionContext): Promise<DetectionResult | null>;
  onActivate?(): Promise<void>;
  onDeactivate?(): Promise<void>;
  healthCheck?(): Promise<{ healthy: boolean; details?: string }>;
}
