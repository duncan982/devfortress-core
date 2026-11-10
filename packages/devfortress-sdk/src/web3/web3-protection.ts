import { z } from 'zod';

export interface Web3ProtectionConfig {
  enableTransactionIntentValidation: boolean;
  enableGasPriceAnomalyDetection: boolean;
  enableDrainerDetection: boolean;
  enableTokenApprovalMonitoring: boolean;
  maxGasPriceGwei?: number;
}

export interface Web3Transaction {
  to: string;
  from: string;
  value: string; // Wei string
  data: string; // Hex string
  gasPrice?: string; // Wei string
}

export interface Web3Result {
  allowed: boolean;
  reason?: string;
  riskScore?: number; // 0-100
}

export class Web3ProtectionEngine {
  private readonly config: Web3ProtectionConfig;

  // Basic signatures for drainer detection (simplified examples)
  private readonly knownDrainerSignatures = [
    '0x0000000000000000000000000000000000000000', // Example null address check
    '0x12345678', // Example bad sig
  ];

  // ERC20 Approve method signature: 0x095ea7b3
  private readonly ERC20_APPROVE_SIG = '0x095ea7b3';

  constructor(
    config: Web3ProtectionConfig = {
      enableTransactionIntentValidation: true,
      enableGasPriceAnomalyDetection: true,
      enableDrainerDetection: true,
      enableTokenApprovalMonitoring: true,
    }
  ) {
    this.config = config;
  }

  public validateTransaction(tx: Web3Transaction): Web3Result {
    let riskScore = 0;

    // 1. Gas Price Anomaly
    if (
      this.config.enableGasPriceAnomalyDetection &&
      tx.gasPrice &&
      this.config.maxGasPriceGwei
    ) {
      const gasPriceGwei = Number(BigInt(tx.gasPrice) / BigInt(10 ** 9));
      if (gasPriceGwei > this.config.maxGasPriceGwei) {
        return {
          allowed: false,
          reason: `Gas price anomaly: ${gasPriceGwei} Gwei exceeds max ${this.config.maxGasPriceGwei} Gwei`,
          riskScore: 80,
        };
      }
    }

    // 2. Drainer Pattern Detection
    if (this.config.enableDrainerDetection && tx.data && tx.data.length >= 10) {
      const methodSig = tx.data.substring(0, 10);
      if (
        this.knownDrainerSignatures.includes(methodSig) ||
        this.knownDrainerSignatures.includes(tx.to)
      ) {
        return {
          allowed: false,
          reason: 'Transaction matches known drainer pattern or destination.',
          riskScore: 100,
        };
      }
    }

    // 3. Token Approval Monitoring
    if (
      this.config.enableTokenApprovalMonitoring &&
      tx.data &&
      tx.data.startsWith(this.ERC20_APPROVE_SIG)
    ) {
      // Simple check for "unlimited" approval (type(uint256).max)
      if (
        tx.data.includes(
          'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
        )
      ) {
        riskScore += 50; // High risk, but maybe allowed depending on policy
        // In a strict mode, we might block this:
        // return { allowed: false, reason: 'Unlimited token approval detected.', riskScore };
      }
    }

    // 4. Basic Intent Validation
    if (this.config.enableTransactionIntentValidation) {
      if (!tx.to || tx.to === '0x') {
        return {
          allowed: false,
          reason: 'Invalid transaction destination.',
          riskScore: 90,
        };
      }
    }

    if (riskScore >= 80) {
      return {
        allowed: false,
        reason: `High risk transaction (Score: ${riskScore})`,
        riskScore,
      };
    }

    return { allowed: true, riskScore };
  }
}
