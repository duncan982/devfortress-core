package net.devfortress;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Shared AES-256-GCM reversible-encryption primitive. Mirrors
 * {@code packages/devfortress-sdk/src/credential-vault.ts}. A generic
 * reversible-encryption primitive
 * {@link ApiKeyAliasingService} and {@code tier2gated.IdentityProjection}/
 * {@code tier2gated.ConsentMatrix} each wire into their own alias-keyed
 * stores.
 */
public final class CredentialVault {
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_IV_BYTES = 12;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final HexFormat HEX = HexFormat.of();

    private CredentialVault() {
    }

    /** A ciphertext bundle: hex-encoded ciphertext, IV, and GCM auth tag. */
    public record VaultEncryptedRecord(String ciphertext, String iv, String authTag) {
    }

    /** Derives a 32-byte AES-256 key from an application secret (UTF-8 text) + context via HKDF-SHA256. */
    public static byte[] deriveVaultKey(String applicationSecret, String context) {
        return deriveVaultKey(applicationSecret.getBytes(StandardCharsets.UTF_8), context);
    }

    /**
     * Derives a 32-byte AES-256 key from an application secret (raw bytes) + context via
     * HKDF-SHA256. Mirrors Node's {@code deriveVaultKey}, which accepts {@code string | Buffer}
     * and uses a Buffer's raw bytes directly rather than UTF-8-encoding a stringified form of
     * them — this overload is that raw-bytes path (e.g. for a hex-decoded master key).
     */
    public static byte[] deriveVaultKey(byte[] applicationSecret, String context) {
        byte[] info = ("devfortress.credential-vault." + context).getBytes(StandardCharsets.UTF_8);
        return hkdfSha256(applicationSecret, new byte[32], info, 32);
    }

    /**
     * RFC 5869 HKDF-SHA256 (extract-and-expand). The JDK has no built-in HKDF; implemented
     * directly via HMAC-SHA256 rather than adding a dependency, matching the SDK's
     * no-runtime-dependencies rule. For a 32-byte output (one HMAC-SHA256 block) this is exactly
     * one expand round, equivalent to Node's {@code crypto.hkdfSync('sha256', ikm, salt, info, 32)}.
     */
    private static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length) {
        if (length != 32) {
            throw new IllegalArgumentException("devfortress: hkdfSha256 here only supports a 32-byte output");
        }
        byte[] prk = hmacSha256(salt, ikm);
        byte[] expandInput = new byte[info.length + 1];
        System.arraycopy(info, 0, expandInput, 0, info.length);
        expandInput[info.length] = 0x01;
        return hmacSha256(prk, expandInput);
    }

    private static byte[] hmacSha256(byte[] key, byte[] message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(message);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Pure primitive: encrypt a real credential with an explicit key. */
    public static VaultEncryptedRecord encrypt(String realCredential, byte[] key) {
        byte[] iv = new byte[GCM_IV_BYTES];
        RANDOM.nextBytes(iv);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] combined = cipher.doFinal(realCredential.getBytes(StandardCharsets.UTF_8));
            int tagBytes = GCM_TAG_BITS / 8;
            byte[] ciphertext = new byte[combined.length - tagBytes];
            byte[] authTag = new byte[tagBytes];
            System.arraycopy(combined, 0, ciphertext, 0, ciphertext.length);
            System.arraycopy(combined, ciphertext.length, authTag, 0, tagBytes);
            return new VaultEncryptedRecord(HEX.formatHex(ciphertext), HEX.formatHex(iv), HEX.formatHex(authTag));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Pure primitive: decrypt a ciphertext bundle with an explicit key. Throws (does not return garbage plaintext) on auth-tag mismatch. */
    public static String decrypt(VaultEncryptedRecord record, byte[] key) {
        byte[] iv = HEX.parseHex(record.iv());
        byte[] ciphertext = HEX.parseHex(record.ciphertext());
        byte[] authTag = HEX.parseHex(record.authTag());
        byte[] combined = new byte[ciphertext.length + authTag.length];
        System.arraycopy(ciphertext, 0, combined, 0, ciphertext.length);
        System.arraycopy(authTag, 0, combined, ciphertext.length, authTag.length);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
            return new String(cipher.doFinal(combined), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            // Auth-tag verification failed (or malformed input) — never return garbage plaintext.
            throw new IllegalArgumentException("devfortress: vault record failed authentication", e);
        }
    }

    /**
     * A self-contained, in-memory vault instance: encrypts + stores real credentials under an
     * alias, later resolves the alias back to plaintext. Used wherever a class needs its own
     * alias-keyed encrypted store (rather than the shared static helpers above).
     */
    public static final class Store {
        private static final int DEFAULT_MAX_ENTRIES = 50_000;
        private final int maxEntries;
        private final Object lock = new Object();
        private final Map<String, Entry> store = new HashMap<>();
        private final List<String> order = new ArrayList<>();

        public Store() {
            this(DEFAULT_MAX_ENTRIES);
        }

        public Store(int maxEntries) {
            this.maxEntries = maxEntries;
        }

        private record Entry(VaultEncryptedRecord record, byte[] key) {
        }

        public VaultEncryptedRecord register(String alias, String realCredential, byte[] key) {
            VaultEncryptedRecord record = encrypt(realCredential, key);
            synchronized (lock) {
                if (store.containsKey(alias)) {
                    order.remove(alias);
                } else if (store.size() >= maxEntries && !order.isEmpty()) {
                    String oldest = order.remove(0);
                    store.remove(oldest);
                }
                store.put(alias, new Entry(record, key));
                order.add(alias);
            }
            return record;
        }

        /** Returns null on an unknown alias. Rejects (throws, does not return garbage plaintext) on auth-tag mismatch. */
        public String resolve(String alias) {
            Entry entry;
            synchronized (lock) {
                entry = store.get(alias);
            }
            if (entry == null) {
                return null;
            }
            return decrypt(entry.record(), entry.key());
        }

        public boolean revoke(String alias) {
            synchronized (lock) {
                order.remove(alias);
                return store.remove(alias) != null;
            }
        }

        public boolean has(String alias) {
            synchronized (lock) {
                return store.containsKey(alias);
            }
        }
    }
}
