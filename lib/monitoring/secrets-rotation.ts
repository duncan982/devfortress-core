/**
 * Secrets Rotation Service
 * Automates rotation of API keys and sensitive credentials
 */

import { Prisma } from '@prisma/client';
import { prisma } from '@core/lib/prisma';
import { logInfo, logError, logWarn } from '@core/lib/logger';
import { sendEmail } from '@core/lib/email/resend';
import * as crypto from 'crypto';

enum SecretType {
  API_KEY = 'API_KEY',
  ACCESS_TOKEN = 'ACCESS_TOKEN',
  DATABASE_PASSWORD = 'DATABASE_PASSWORD',
  WEBHOOK_SECRET = 'WEBHOOK_SECRET',
  ENCRYPTION_KEY = 'ENCRYPTION_KEY',
}

enum SecretStatus {
  ACTIVE = 'ACTIVE',
  ROTATING = 'ROTATING',
  DEPRECATED = 'DEPRECATED',
  REVOKED = 'REVOKED',
}

enum RotationStrategy {
  MANUAL = 'MANUAL',
  SCHEDULED = 'SCHEDULED',
  ON_DEMAND = 'ON_DEMAND',
  EMERGENCY = 'EMERGENCY',
}

interface Secret {
  id: string;
  userId: string;
  teamId?: string;
  name: string;
  type: SecretType;
  value: string; // Encrypted
  status: SecretStatus;
  lastRotatedAt: Date;
  nextRotationAt?: Date;
  rotationIntervalDays: number;
  metadata?: Record<string, unknown>;
}

interface RotationConfig {
  secretId: string;
  strategy: RotationStrategy;
  notifyEmail?: string;
  gracePeriodDays?: number; // Time before old secret is revoked
}

interface RotationResult {
  success: boolean;
  secretId: string;
  oldValue?: string; // For temporary grace period
  newValue: string;
  expiresAt?: Date;
  error?: string;
}

export class SecretsRotationService {
  private static readonly ENCRYPTION_ALGORITHM = 'aes-256-gcm';
  private static readonly ENCRYPTION_KEY =
    process.env.SECRETS_ENCRYPTION_KEY || '';

  /**
   * Encrypt a secret value
   */
  private static encrypt(value: string): string {
    if (!this.ENCRYPTION_KEY) {
      throw new Error('SECRETS_ENCRYPTION_KEY not configured');
    }

    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(
      this.ENCRYPTION_ALGORITHM,
      Buffer.from(this.ENCRYPTION_KEY, 'hex'),
      iv
    );

    let encrypted = cipher.update(value, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();

    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
  }

  /**
   * Decrypt a secret value
   */
  private static decrypt(encrypted: string): string {
    if (!this.ENCRYPTION_KEY) {
      throw new Error('SECRETS_ENCRYPTION_KEY not configured');
    }

    const [ivHex, authTagHex, encryptedData] = encrypted.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');

    const decipher = crypto.createDecipheriv(
      this.ENCRYPTION_ALGORITHM,
      Buffer.from(this.ENCRYPTION_KEY, 'hex'),
      iv
    );
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }

  /**
   * Generate a secure random secret
   */
  static generateSecret(length: number = 32): string {
    return crypto.randomBytes(length).toString('base64url');
  }

  /**
   * Store a new secret
   */
  static async storeSecret(config: {
    userId: string;
    teamId?: string;
    name: string;
    type: SecretType;
    value: string;
    rotationIntervalDays?: number;
    metadata?: Prisma.InputJsonValue | null;
  }) {
    try {
      logInfo('Storing new secret', { name: config.name, type: config.type });

      const encryptedValue = this.encrypt(config.value);
      const rotationIntervalDays = config.rotationIntervalDays || 90;

      const secret = await prisma.secret.create({
        data: {
          userId: config.userId,
          teamId: config.teamId,
          name: config.name,
          type: config.type,
          value: encryptedValue,
          status: SecretStatus.ACTIVE,
          lastRotatedAt: new Date(),
          nextRotationAt: new Date(
            Date.now() + rotationIntervalDays * 24 * 60 * 60 * 1000
          ),
          rotationIntervalDays,
          metadata: config.metadata ?? Prisma.JsonNull,
        },
      });

      logInfo('Secret stored successfully', { secretId: secret.id });
      return secret;
    } catch (error) {
      logError('Failed to store secret', { error, name: config.name });
      throw error;
    }
  }

  /**
   * Rotate a secret
   */
  static async rotateSecret(config: RotationConfig): Promise<RotationResult> {
    try {
      logInfo('Rotating secret', {
        secretId: config.secretId,
        strategy: config.strategy,
      });

      const secret = await prisma.secret.findUnique({
        where: { id: config.secretId },
      });

      if (!secret) {
        throw new Error('Secret not found');
      }

      // Generate new secret value
      const newValue = this.generateSecret();
      const encryptedNewValue = this.encrypt(newValue);

      // Update secret with new value
      await prisma.secret.update({
        where: { id: config.secretId },
        data: {
          value: encryptedNewValue,
          lastRotatedAt: new Date(),
          nextRotationAt: new Date(
            Date.now() + secret.rotationIntervalDays * 24 * 60 * 60 * 1000
          ),
        },
      });

      // Log rotation event
      await prisma.secretRotationLog.create({
        data: {
          secretId: config.secretId,
          strategy: config.strategy,
          previousValue: secret.value, // Keep encrypted old value for grace period
          newValue: encryptedNewValue,
          rotatedAt: new Date(),
          expiresAt: config.gracePeriodDays
            ? new Date(
                Date.now() + config.gracePeriodDays * 24 * 60 * 60 * 1000
              )
            : null,
        },
      });

      logInfo('Secret rotated successfully', {
        secretId: config.secretId,
        strategy: config.strategy,
      });

      // Send notification if email configured
      if (config.notifyEmail) {
        await this.sendRotationNotification(
          config.notifyEmail,
          secret.name,
          newValue
        );
      }

      return {
        success: true,
        secretId: config.secretId,
        oldValue: config.gracePeriodDays
          ? this.decrypt(secret.value)
          : undefined,
        newValue,
        expiresAt: config.gracePeriodDays
          ? new Date(Date.now() + config.gracePeriodDays * 24 * 60 * 60 * 1000)
          : undefined,
      };
    } catch (error) {
      logError('Failed to rotate secret', { error, secretId: config.secretId });
      return {
        success: false,
        secretId: config.secretId,
        newValue: '',
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Get a secret value (decrypted)
   */
  static async getSecret(secretId: string): Promise<string> {
    try {
      const secret = await prisma.secret.findUnique({
        where: { id: secretId },
      });

      if (!secret) {
        throw new Error('Secret not found');
      }

      if (secret.status === SecretStatus.REVOKED) {
        throw new Error('Secret has been revoked');
      }

      return this.decrypt(secret.value);
    } catch (error) {
      logError('Failed to get secret', { error, secretId });
      throw error;
    }
  }

  /**
   * List all secrets for a user/team
   */
  static async listSecrets(userId: string, teamId?: string) {
    try {
      const secrets = await prisma.secret.findMany({
        where: {
          OR: [{ userId }, { teamId: teamId || undefined }],
          status: { not: SecretStatus.REVOKED },
        },
        select: {
          id: true,
          name: true,
          type: true,
          status: true,
          lastRotatedAt: true,
          nextRotationAt: true,
          rotationIntervalDays: true,
          metadata: true,
          createdAt: true,
          // Exclude the encrypted value from list view
        },
        orderBy: { createdAt: 'desc' },
      });

      return secrets;
    } catch (error) {
      logError('Failed to list secrets', { error, userId });
      throw error;
    }
  }

  /**
   * Check for secrets that need rotation
   */
  static async checkSecretsNeedingRotation() {
    try {
      const secrets = await prisma.secret.findMany({
        where: {
          status: SecretStatus.ACTIVE,
          nextRotationAt: {
            lte: new Date(),
          },
        },
        include: {
          user: {
            select: {
              email: true,
              name: true,
            },
          },
        },
      });

      logInfo('Found secrets needing rotation', { count: secrets.length });

      for (const secret of secrets) {
        logWarn('Secret requires rotation', {
          secretId: secret.id,
          name: secret.name,
          nextRotationAt: secret.nextRotationAt,
        });

        // Send alert to user
        if (secret.user.email) {
          await sendEmail({
            to: secret.user.email,
            subject: `Action Required: Rotate Secret "${secret.name}"`,
            html: `
              <h2>Secret Rotation Required</h2>
              <p>Hello ${secret.user.name || 'there'},</p>
              <p>Your secret "<strong>${secret.name}</strong>" is due for rotation.</p>
              <p><strong>Type:</strong> ${secret.type}</p>
              <p><strong>Last Rotated:</strong> ${secret.lastRotatedAt.toISOString()}</p>
              <p><strong>Rotation Due:</strong> ${secret.nextRotationAt?.toISOString() || 'N/A'}</p>
              <p>Please rotate this secret as soon as possible to maintain security best practices.</p>
              <p>You can rotate it from your dashboard or via the API.</p>
            `,
          });
        }
      }

      return secrets;
    } catch (error) {
      logError('Failed to check secrets needing rotation', { error });
      throw error;
    }
  }

  /**
   * Revoke a secret immediately
   */
  static async revokeSecret(secretId: string) {
    try {
      logInfo('Revoking secret', { secretId });

      const secret = await prisma.secret.update({
        where: { id: secretId },
        data: { status: SecretStatus.REVOKED },
      });

      logInfo('Secret revoked', { secretId });
      return secret;
    } catch (error) {
      logError('Failed to revoke secret', { error, secretId });
      throw error;
    }
  }

  /**
   * Get rotation history for a secret
   */
  static async getRotationHistory(secretId: string, limit = 20) {
    try {
      const history = await prisma.secretRotationLog.findMany({
        where: { secretId },
        orderBy: { rotatedAt: 'desc' },
        take: limit,
        select: {
          id: true,
          strategy: true,
          rotatedAt: true,
          expiresAt: true,
          // Exclude actual secret values
        },
      });

      return history;
    } catch (error) {
      logError('Failed to get rotation history', { error, secretId });
      throw error;
    }
  }

  /**
   * Send rotation notification email
   */
  private static async sendRotationNotification(
    email: string,
    secretName: string,
    newValue: string
  ) {
    try {
      await sendEmail({
        to: email,
        subject: `Secret Rotated: ${secretName}`,
        html: `
          <h2>Secret Successfully Rotated</h2>
          <p>Your secret "<strong>${secretName}</strong>" has been rotated.</p>
          <p><strong>New Value:</strong> <code>${newValue}</code></p>
          <p><em>This is the only time you will see the new value. Please store it securely.</em></p>
          <p>If you did not request this rotation, please contact support immediately.</p>
        `,
      });

      logInfo('Rotation notification sent', { email, secretName });
    } catch (error) {
      logError('Failed to send rotation notification', { error, email });
    }
  }
}

export { SecretType, SecretStatus, RotationStrategy };
export type { Secret, RotationConfig, RotationResult };
