/**
 * Open-core stub — the real M-Pesa (Kenya fintech, S36) protection module is
 * a "post-MVP" feature excluded from this build. See open-core-strip.sh
 * Op 14.
 *
 * Never wired into DevFortressCore itself (opt-in-only, confirmed by
 * grepping devfortress.ts for every symbol below before writing this).
 * Fails closed: every validator reports failure/blocked rather than
 * accepting a callback this build cannot actually verify.
 */
export interface MpesaStkCallback {
  [key: string]: unknown;
}
export interface MpesaC2BCallback {
  [key: string]: unknown;
}
export interface MpesaB2CCallback {
  [key: string]: unknown;
}

function notAvailable(): { success: false; error: string } {
  return {
    success: false,
    error: 'M-Pesa protection module is not available in the open-core build',
  };
}

export function validateMpesaCallback(_payload: unknown) {
  return notAvailable();
}
export function validateStkCallback(_payload: unknown) {
  return notAvailable();
}
export function validateC2BCallback(_payload: unknown) {
  return notAvailable();
}
export function validateB2CCallback(_payload: unknown) {
  return notAvailable();
}

export function isDuplicateReceipt(_receiptNumber: string): boolean {
  return false;
}
export function markReceiptSeen(_receiptNumber: string): void {}

export function isAllowedMpesaIp(_ip: string): boolean {
  return false;
}
export function getSafaricomIpList(): string[] {
  return [];
}

export interface MpesaAnomalyInput {
  initiatedAt: Date | string;
  callbackAt: Date | string;
  expectedAmount?: number;
  actualAmount?: number;
  timingWindowSeconds?: number;
  amountTolerancePercent?: number;
}

export interface MpesaAnomalyResult {
  timingAnomaly: boolean;
  amountAnomaly: boolean;
  details: string[];
}

export function checkMpesaAnomalies(
  _input: MpesaAnomalyInput
): MpesaAnomalyResult {
  return { timingAnomaly: false, amountAnomaly: false, details: [] };
}

export interface MpesaProtectionConfig {
  timingWindowSeconds?: number;
  amountTolerancePercent?: number;
  strictIpCheck?: boolean;
}

export interface MpesaProtectionResult {
  valid: boolean;
  blocked: boolean;
  reason?: string;
  anomalies?: string[];
}

export function enableMpesaProtection(_config: MpesaProtectionConfig = {}) {
  return function protectMpesaCallback(_input: {
    payload: unknown;
    sourceIp: string;
    receiptNumber?: string;
    initiatedAt?: Date | string;
    expectedAmount?: number;
    actualAmount?: number;
  }): MpesaProtectionResult {
    return {
      valid: false,
      blocked: true,
      reason: 'M-Pesa protection module is not available in the open-core build',
    };
  };
}
