using System.Security.Cryptography;

namespace DevFortress;

/// <summary>
/// Shared AES-256-GCM reversible-encryption primitive. Mirrors
/// <c>packages/devfortress-sdk/src/credential-vault.ts</c>. A generic
/// reversible-encryption primitive <see cref="ApiKeyAliasingService"/>
/// and <c>Tier2Gated.IdentityProjection</c>/<c>Tier2Gated.ConsentMatrix</c> each wire into their
/// own alias-keyed stores.
/// </summary>
public static class CredentialVault
{
    /// <summary>A ciphertext bundle: hex-encoded ciphertext, IV, and GCM auth tag.</summary>
    public sealed record VaultEncryptedRecord(string Ciphertext, string Iv, string AuthTag);

    /// <summary>Derives a 32-byte AES-256 key from an application secret (UTF-8 text) + context via HKDF-SHA256.</summary>
    public static byte[] DeriveVaultKey(string applicationSecret, string context) =>
        DeriveVaultKey(System.Text.Encoding.UTF8.GetBytes(applicationSecret), context);

    /// <summary>
    /// Derives a 32-byte AES-256 key from an application secret (raw bytes) + context via
    /// HKDF-SHA256. Mirrors Node's <c>deriveVaultKey</c>, which accepts <c>string | Buffer</c>
    /// and uses a Buffer's raw bytes directly rather than UTF-8-encoding a stringified form of
    /// them — this overload is that raw-bytes path (e.g. for a hex-decoded master key).
    /// </summary>
    public static byte[] DeriveVaultKey(byte[] applicationSecret, string context)
    {
        byte[] info = System.Text.Encoding.UTF8.GetBytes($"devfortress.credential-vault.{context}");
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, applicationSecret, 32, salt: new byte[32], info: info);
    }

    /// <summary>Pure primitive: encrypt a real credential with an explicit key.</summary>
    public static VaultEncryptedRecord Encrypt(string realCredential, byte[] key)
    {
        byte[] iv = RandomNumberGenerator.GetBytes(12);
        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes(realCredential);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] authTag = new byte[16];
        using var aes = new AesGcm(key, authTag.Length);
        aes.Encrypt(iv, plaintext, ciphertext, authTag);
        return new VaultEncryptedRecord(Convert.ToHexString(ciphertext).ToLowerInvariant(),
            Convert.ToHexString(iv).ToLowerInvariant(), Convert.ToHexString(authTag).ToLowerInvariant());
    }

    /// <summary>Pure primitive: decrypt a ciphertext bundle. Throws (does not return garbage plaintext) on auth-tag mismatch.</summary>
    public static string Decrypt(VaultEncryptedRecord record, byte[] key)
    {
        byte[] iv = Convert.FromHexString(record.Iv);
        byte[] ciphertext = Convert.FromHexString(record.Ciphertext);
        byte[] authTag = Convert.FromHexString(record.AuthTag);
        byte[] plaintext = new byte[ciphertext.Length];
        using var aes = new AesGcm(key, authTag.Length);
        aes.Decrypt(iv, ciphertext, authTag, plaintext);
        return System.Text.Encoding.UTF8.GetString(plaintext);
    }

    /// <summary>
    /// A self-contained, in-memory vault instance: encrypts + stores real credentials under an
    /// alias, later resolves the alias back to plaintext. Used wherever a class needs its own
    /// alias-keyed encrypted store (rather than the shared static helpers above).
    /// </summary>
    public sealed class Store
    {
        private const int DefaultMaxEntries = 50_000;
        private readonly int _maxEntries;
        private readonly object _lock = new();
        private readonly Dictionary<string, (VaultEncryptedRecord Record, byte[] Key)> _store = [];
        private readonly List<string> _order = [];

        public Store(int maxEntries = DefaultMaxEntries) => _maxEntries = maxEntries;

        public VaultEncryptedRecord Register(string alias, string realCredential, byte[] key)
        {
            var record = Encrypt(realCredential, key);
            lock (_lock)
            {
                if (_store.ContainsKey(alias))
                {
                    _order.Remove(alias);
                }
                else if (_store.Count >= _maxEntries && _order.Count > 0)
                {
                    string oldest = _order[0];
                    _order.RemoveAt(0);
                    _store.Remove(oldest);
                }
                _store[alias] = (record, key);
                _order.Add(alias);
            }
            return record;
        }

        /// <summary>Returns null on an unknown alias. Rejects (does not return garbage plaintext) on auth-tag mismatch.</summary>
        public string? Resolve(string alias)
        {
            (VaultEncryptedRecord Record, byte[] Key) entry;
            lock (_lock)
            {
                if (!_store.TryGetValue(alias, out entry))
                {
                    return null;
                }
            }
            return Decrypt(entry.Record, entry.Key);
        }

        public bool Revoke(string alias)
        {
            lock (_lock)
            {
                _order.Remove(alias);
                return _store.Remove(alias);
            }
        }

        public bool Has(string alias)
        {
            lock (_lock)
            {
                return _store.ContainsKey(alias);
            }
        }
    }
}
