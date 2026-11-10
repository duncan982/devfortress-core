import { DevFortress } from '../index';
import crypto from 'crypto';

export interface PipelineSecurityOptions {
  enabled?: boolean;
  strictMode?: boolean;
  blockedSignatures?: string[];
  alertOnly?: boolean;
}

export interface WebhookValidationOptions {
  secret: string;
  signatureHeader?: string;
  hashAlgorithm?: 'sha1' | 'sha256';
  enforceIPAllowlist?: boolean;
  allowedIPs?: string[];
}

/**
 * DevFortress SPEC-C35: DevOps & CI/CD Pipeline Security
 * Protects pipeline infrastructure, validates webhooks, and prevents credential leakage.
 */
export class PipelineSecurityModule {
  private df: DevFortress;
  private options: PipelineSecurityOptions;

  constructor(df: DevFortress, options: PipelineSecurityOptions = {}) {
    this.df = df;
    this.options = {
      enabled: true,
      strictMode: false,
      alertOnly: false,
      ...options,
    };
  }

  /**
   * Scans the current environment for potentially exposed raw secrets.
   * Promotes the use of DevFortress aliases over raw keys.
   */
  public async scanEnvironmentForExposedSecrets(): Promise<{
    safe: boolean;
    findings: string[];
  }> {
    if (!this.options.enabled) return { safe: true, findings: [] };

    const findings: string[] = [];
    const sensitivePatterns = [
      /sk_live_[a-zA-Z0-9]+/, // Common API key format
      /xoxb-[a-zA-Z0-9]+/, // Slack bot token
      /ghp_[a-zA-Z0-9]+/, // GitHub personal access token
      /-----BEGIN RSA PRIVATE KEY-----/,
    ];

    for (const [key, value] of Object.entries(process.env)) {
      if (!value) continue;

      for (const pattern of sensitivePatterns) {
        if (pattern.test(value)) {
          findings.push(
            `Potentially exposed raw secret in environment variable: ${key}`
          );

          await this.df.observe(
            {
              ip: 'pipeline',
              method: 'PIPELINE_SCAN',
              path: `/pipeline/secrets/${key}`,
              headers: {
                'x-pipeline-event': 'environment_secret_exposure',
              },
            },
            {
              meta: {
                eventType: 'pipeline_security_alert',
                severity: 'HIGH',
                recommendation:
                  'Replace raw secret with a DevFortress credential alias (REDACTED)',
              },
            }
          );
        }
      }
    }

    if (
      findings.length > 0 &&
      this.options.strictMode &&
      !this.options.alertOnly
    ) {
      throw new Error(
        `Pipeline Security Violation: Raw secrets detected in environment. Use DevFortress aliases instead.\n${findings.join('\n')}`
      );
    }

    return { safe: findings.length === 0, findings };
  }

  /**
   * Validates inbound CI/CD webhooks (e.g., from GitHub, GitLab) securely
   * against timing attacks and signature spoofing.
   */
  public async validateWebhook(
    payload: string | Buffer,
    headers: Record<string, string | string[] | undefined>,
    options: WebhookValidationOptions
  ): Promise<boolean> {
    if (!this.options.enabled) return true;

    const signatureHeader = options.signatureHeader || 'x-hub-signature-256';
    const rawSignature = headers[signatureHeader];

    let signature = '';
    if (Array.isArray(rawSignature)) {
      signature = rawSignature[0];
    } else if (typeof rawSignature === 'string') {
      signature = rawSignature;
    }

    if (!signature) {
      await this.df.observe(
        {
          ip: 'pipeline',
          method: 'WEBHOOK',
          path: '/pipeline/webhook',
        },
        {
          meta: {
            eventType: 'pipeline_webhook_violation',
            severity: 'MEDIUM',
            reason: 'Missing signature header',
          },
        }
      );
      if (this.options.strictMode && !this.options.alertOnly) return false;
      return false;
    }

    const algo = options.hashAlgorithm || 'sha256';
    const hmac = crypto.createHmac(algo, options.secret);
    hmac.update(payload);

    const expectedSignature = `${algo === 'sha256' ? 'sha256=' : 'sha1='}${hmac.digest('hex')}`;

    try {
      const isValid = crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expectedSignature)
      );

      if (!isValid) {
        await this.df.observe(
          {
            ip: 'pipeline',
            method: 'WEBHOOK',
            path: '/pipeline/webhook',
          },
          {
            meta: {
              eventType: 'pipeline_webhook_violation',
              severity: 'CRITICAL',
              reason: 'Signature mismatch',
            },
          }
        );

        if (this.options.strictMode && !this.options.alertOnly) {
          throw new Error(
            'Pipeline Security Violation: Invalid webhook signature'
          );
        }
      }

      return isValid;
    } catch (err) {
      // Catch unequal buffer lengths
      await this.df.observe(
        {
          ip: 'pipeline',
          method: 'WEBHOOK',
          path: '/pipeline/webhook',
        },
        {
          meta: {
            eventType: 'pipeline_webhook_violation',
            severity: 'CRITICAL',
            reason: 'Signature format invalid',
          },
        }
      );
      return false;
    }
  }
}
