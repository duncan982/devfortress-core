/**
 * DevFortress SDK — shared AES-256-GCM reversible-encryption primitive.
 *
 * Mirrors packages/core/lib/credential-vault.ts on the platform side — the
 * SDK package builds independently (own rootDir, published separately as
 * `devfortress-sdk`) so it can't import the platform file directly. Keep
 * both in sync.
 *
 * reversible-encryption primitive api-key-aliasing.ts,
 * agent-identity/identity-projection.ts, and
 * alias-keyed stores.
 *
 * Key derivation follows the same HKDF-from-application-secret pattern as
 * agent-identity/alias-generator.ts's `hkdfAlias` (crypto.hkdfSync with a
 * zero salt and a namespaced info string).
 *
 * @packageDocumentation
 */

import crypto from 'crypto';

export interface VaultEncryptedRecord {
  ciphertext: string; // hex
  iv: string; // hex
  authTag: string; // hex
}

interface StoredRecord extends VaultEncryptedRecord {
  key: Buffer;
}

const MAX_TRACKED_RECORDS = 50_000;

/**
 * Derive a 32-byte AES-256 key from an application secret + context via
 * HKDF-SHA256. Same call shape as alias-generator.ts's hkdfAlias.
 */
export function deriveVaultKey(
  applicationSecret: string | Buffer,
  context: string
): Buffer {
  const secretBuffer = Buffer.isBuffer(applicationSecret)
    ? applicationSecret
    : Buffer.from(applicationSecret, 'utf8');
  const info = Buffer.from(`devfortress.credential-vault.${context}`);
  return Buffer.from(
    crypto.hkdfSync('sha256', secretBuffer, Buffer.alloc(32), info, 32)
  );
}

/** Pure primitive: encrypt a real credential with an explicit key. */
export function encrypt(
  realCredential: string,
  key: Buffer
): VaultEncryptedRecord {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let ciphertext = cipher.update(realCredential, 'utf8', 'hex');
  ciphertext += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  return { ciphertext, iv: iv.toString('hex'), authTag };
}

/** Pure primitive: decrypt a ciphertext bundle with an explicit key. Throws (does not return garbage plaintext) on auth-tag mismatch. */
export function decrypt(record: VaultEncryptedRecord, key: Buffer): string {
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(record.iv, 'hex')
  );
  decipher.setAuthTag(Buffer.from(record.authTag, 'hex'));
  let plaintext = decipher.update(record.ciphertext, 'hex', 'utf8');
  plaintext += decipher.final('utf8');
  return plaintext;
}

/**
 * A self-contained, in-memory vault instance: encrypts + stores real
 * credentials under an alias, later resolves the alias back to plaintext.
 * Used wherever a class needs its own alias-keyed encrypted store (rather
 * than the shared module-level store the bare functions above imply).
 */
export class CredentialVault {
  private readonly store = new Map<string, StoredRecord>();

  constructor(private readonly maxEntries: number = MAX_TRACKED_RECORDS) {}

  register(
    alias: string,
    realCredential: string,
    key: Buffer
  ): VaultEncryptedRecord {
    const record = encrypt(realCredential, key);
    if (this.store.has(alias)) {
      this.store.delete(alias);
    } else if (this.store.size >= this.maxEntries) {
      const oldest = this.store.keys().next().value;
      if (oldest !== undefined) this.store.delete(oldest);
    }
    this.store.set(alias, { ...record, key });
    return record;
  }

  /** Rejects (does not return garbage plaintext) on auth-tag mismatch. */
  resolve(alias: string): string | null {
    const stored = this.store.get(alias);
    if (!stored) return null;
    return decrypt(stored, stored.key);
  }

  revoke(alias: string): boolean {
    return this.store.delete(alias);
  }

  has(alias: string): boolean {
    return this.store.has(alias);
  }
}
