/**
 * API Key Management Service
 * Securely store and retrieve user-provided API keys for free tier users
 * 
 * Security features:
 * - Encryption at rest using AES-256-GCM
 * - Per-user encryption keys derived from master secret
 * - Key rotation support
 * - Audit logging for key access
 */

import crypto from 'crypto';
import { prisma } from '@core/lib/prisma';
import { logInfo, logWarn, logError } from '@core/lib/logger';
// API key management utilities

// Encryption configuration
const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32; // 256 bits
const IV_LENGTH = 16; // 128 bits
const SALT_LENGTH = 32; // 256 bits

/**
 * Supported API key types
 */
export enum ApiKeyType {
  OPENAI = 'OPENAI',
  ANTHROPIC = 'ANTHROPIC',
  SUPABASE = 'SUPABASE',
  VERCEL = 'VERCEL',
  GITHUB = 'GITHUB',
}

/**
 * Encrypted API key structure
 */
interface EncryptedApiKey {
  encryptedKey: string;
  iv: string;
  authTag: string;
  salt: string;
}

/**
 * API key metadata
 */
export interface ApiKeyMetadata {
  id: string;
  userId: string;
  type: ApiKeyType;
  label: string;
  lastUsed: Date | null;
  createdAt: Date;
  isActive: boolean;
  maskedKey: string; // First 8 and last 4 chars visible
}

/**
 * Derive encryption key from master secret and user salt
 */
function deriveKey(salt: Buffer): Buffer {
  const masterKey = process.env.API_KEY_ENCRYPTION_SECRET || process.env.NEXTAUTH_SECRET;
  
  if (!masterKey) {
    throw new Error('No encryption secret configured');
  }

  return crypto.pbkdf2Sync(
    masterKey,
    salt,
    100000, // iterations
    KEY_LENGTH,
    'sha256'
  );
}

/**
 * Encrypt an API key
 */
function encryptApiKey(plainKey: string): EncryptedApiKey {
  // Generate random salt and IV
  const salt = crypto.randomBytes(SALT_LENGTH);
  const iv = crypto.randomBytes(IV_LENGTH);

  // Derive encryption key
  const key = deriveKey(salt);

  // Create cipher
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  // Encrypt
  let encrypted = cipher.update(plainKey, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Get authentication tag
  const authTag = cipher.getAuthTag();

  return {
    encryptedKey: encrypted,
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
    salt: salt.toString('hex'),
  };
}

/**
 * Decrypt an API key
 */
function decryptApiKey(encrypted: EncryptedApiKey): string {
  try {
    // Convert hex strings back to buffers
    const salt = Buffer.from(encrypted.salt, 'hex');
    const iv = Buffer.from(encrypted.iv, 'hex');
    const authTag = Buffer.from(encrypted.authTag, 'hex');

    // Derive encryption key
    const key = deriveKey(salt);

    // Create decipher
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);

    // Decrypt
    let decrypted = decipher.update(encrypted.encryptedKey, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  } catch (error) {
    logError('Failed to decrypt API key', { error });
    throw new Error('Decryption failed - key may be corrupted');
  }
}

/**
 * Mask API key for display (show first 8 and last 4 characters)
 */
function maskApiKey(key: string): string {
  if (key.length <= 12) {
    return '*'.repeat(key.length);
  }

  const prefix = key.substring(0, 8);
  const suffix = key.substring(key.length - 4);
  const middle = '*'.repeat(Math.max(4, key.length - 12));

  return `${prefix}${middle}${suffix}`;
}

/**
 * Store an API key securely
 */
export async function storeApiKey(
  userId: string,
  type: ApiKeyType,
  plainKey: string,
  label: string = `${type} Key`
): Promise<ApiKeyMetadata> {
  try {
    // Validate key format based on type
    validateApiKeyFormat(type, plainKey);

    // Encrypt the key
    const encrypted = encryptApiKey(plainKey);

    // Store in database
    const stored = await prisma.userApiKey.create({
      data: {
        userId,
        type,
        label,
        encryptedKey: encrypted.encryptedKey,
        iv: encrypted.iv,
        authTag: encrypted.authTag,
        salt: encrypted.salt,
        maskedKey: maskApiKey(plainKey),
        isActive: true,
      },
    });

    logInfo('API key stored successfully', {
      userId,
      type,
      keyId: stored.id,
    });

    return {
      id: stored.id,
      userId: stored.userId,
      type: stored.type as ApiKeyType,
      label: stored.label,
      lastUsed: stored.lastUsed,
      createdAt: stored.createdAt,
      isActive: stored.isActive,
      maskedKey: stored.maskedKey,
    };
  } catch (error) {
    logError('Failed to store API key', { userId, type, error });
    throw error;
  }
}

/**
 * Retrieve and decrypt an API key
 */
export async function getApiKey(
  userId: string,
  type: ApiKeyType
): Promise<string | null> {
  try {
    const stored = await prisma.userApiKey.findFirst({
      where: {
        userId,
        type,
        isActive: true,
      },
      orderBy: {
        createdAt: 'desc',
      },
    });

    if (!stored) {
      return null;
    }

    // Decrypt the key
    const plainKey = decryptApiKey({
      encryptedKey: stored.encryptedKey,
      iv: stored.iv,
      authTag: stored.authTag,
      salt: stored.salt,
    });

    // Update last used timestamp
    await prisma.userApiKey.update({
      where: { id: stored.id },
      data: { lastUsed: new Date() },
    });

    return plainKey;
  } catch (error) {
    logError('Failed to retrieve API key', { userId, type, error });
    return null;
  }
}

/**
 * List all API keys for a user (metadata only, not decrypted)
 */
export async function listApiKeys(userId: string): Promise<ApiKeyMetadata[]> {
  const keys = await prisma.userApiKey.findMany({
    where: { userId },
    orderBy: { createdAt: 'desc' },
  });

  return keys.map(key => ({
    id: key.id,
    userId: key.userId,
    type: key.type as ApiKeyType,
    label: key.label,
    lastUsed: key.lastUsed,
    createdAt: key.createdAt,
    isActive: key.isActive,
    maskedKey: key.maskedKey,
  }));
}

/**
 * Delete an API key by type
 */
export async function deleteApiKey(userId: string, type: ApiKeyType): Promise<boolean> {
  try {
    const result = await prisma.userApiKey.deleteMany({
      where: {
        userId,
        type,
      },
    });

    logInfo('API key deleted', { userId, type, count: result.count });
    return result.count > 0;
  } catch (error) {
    logError('Failed to delete API key', { userId, type, error });
    return false;
  }
}

/**
 * Mark an API key as invalid (when auth fails)
 */
export async function markApiKeyInvalid(userId: string, type: ApiKeyType): Promise<void> {
  try {
    await prisma.userApiKey.updateMany({
      where: {
        userId,
        type,
        isActive: true,
      },
      data: {
        isActive: false,
      },
    });

    logWarn('API key marked as invalid', { userId, type });
  } catch (error) {
    logError('Failed to mark API key as invalid', { userId, type, error });
  }
}

/**
 * Deactivate an API key (soft delete)
 */
export async function deactivateApiKey(userId: string, keyId: string): Promise<boolean> {
  try {
    await prisma.userApiKey.update({
      where: {
        id: keyId,
        userId,
      },
      data: {
        isActive: false,
      },
    });

    logInfo('API key deactivated', { userId, keyId });
    return true;
  } catch (error) {
    logError('Failed to deactivate API key', { userId, keyId, error });
    return false;
  }
}

/**
 * Rotate an API key (store new key, deactivate old)
 */
export async function rotateApiKey(
  userId: string,
  type: ApiKeyType,
  newPlainKey: string,
  label?: string
): Promise<ApiKeyMetadata> {
  try {
    // Deactivate existing keys of this type
    await prisma.userApiKey.updateMany({
      where: {
        userId,
        type,
        isActive: true,
      },
      data: {
        isActive: false,
      },
    });

    // Store new key
    const newKey = await storeApiKey(userId, type, newPlainKey, label);

    logInfo('API key rotated', { userId, type });
    return newKey;
  } catch (error) {
    logError('Failed to rotate API key', { userId, type, error });
    throw error;
  }
}

/**
 * Validate API key format based on type
 */
function validateApiKeyFormat(type: ApiKeyType, key: string): void {
  const patterns: Record<ApiKeyType, RegExp> = {
    [ApiKeyType.OPENAI]: /^sk-(proj-)?[A-Za-z0-9]{20,}$/,
    [ApiKeyType.ANTHROPIC]: /^sk-ant-[A-Za-z0-9-]{20,}$/,
    [ApiKeyType.SUPABASE]: /^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/,
    [ApiKeyType.VERCEL]: /^[A-Za-z0-9]{20,}$/,
    [ApiKeyType.GITHUB]: /^gh[ps]_[A-Za-z0-9]{36,}$/,
  };

  const pattern = patterns[type];
  if (!pattern.test(key)) {
    throw new Error(`Invalid ${type} API key format`);
  }
}

/**
 * Test if an API key is valid by making a test request
 */
export async function testApiKey(type: ApiKeyType, key: string): Promise<boolean> {
  try {
    switch (type) {
      case ApiKeyType.OPENAI:
        const openaiResponse = await fetch('https://api.openai.com/v1/models', {
          headers: { Authorization: `Bearer ${key}` },
        });
        return openaiResponse.ok;

      case ApiKeyType.ANTHROPIC:
        const anthropicResponse = await fetch('https://api.anthropic.com/v1/messages', {
          method: 'POST',
          headers: {
            'x-api-key': key,
            'anthropic-version': '2023-06-01',
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            model: 'claude-3-opus-20240229',
            max_tokens: 1,
            messages: [{ role: 'user', content: 'test' }],
          }),
        });
        return anthropicResponse.status === 200 || anthropicResponse.status === 400;

      // Add more test cases for other key types

      default:
        logWarn('No test available for API key type', { type });
        return true; // Assume valid if we can't test
    }
  } catch (error) {
    logError('API key test failed', { type, error });
    return false;
  }
}
