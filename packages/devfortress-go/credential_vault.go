package devfortress

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// VaultEncryptedRecord is an AES-256-GCM encrypted bundle: ciphertext, IV
// and auth tag, each hex-encoded. Mirrors the Node SDK's
// credential-vault.ts shape field-for-field.
type VaultEncryptedRecord struct {
	Ciphertext string
	IV         string
	AuthTag    string
}

type storedRecord struct {
	VaultEncryptedRecord
	key []byte
}

const maxTrackedRecords = 50_000

// DeriveVaultKey derives a 32-byte AES-256 key from an application secret
// and a context string via HKDF-SHA256, matching the Node SDK's
// deriveVaultKey (same zero salt, same namespaced info string).
func DeriveVaultKey(applicationSecret, context string) ([]byte, error) {
	info := []byte("devfortress.credential-vault." + context)
	key, err := hkdf.Key(sha256.New, []byte(applicationSecret), make([]byte, 32), string(info), 32)
	if err != nil {
		return nil, fmt.Errorf("devfortress: derive vault key: %w", err)
	}
	return key, nil
}

// EncryptCredential is a pure primitive: encrypts a real credential with
// an explicit 32-byte key.
func EncryptCredential(realCredential string, key []byte) (VaultEncryptedRecord, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return VaultEncryptedRecord{}, fmt.Errorf("devfortress: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return VaultEncryptedRecord{}, fmt.Errorf("devfortress: new gcm: %w", err)
	}
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return VaultEncryptedRecord{}, fmt.Errorf("devfortress: generate iv: %w", err)
	}
	sealed := gcm.Seal(nil, iv, []byte(realCredential), nil)
	// Go's GCM.Seal appends the auth tag to the ciphertext; split it back
	// out so the wire shape matches Node's {ciphertext, iv, authTag}.
	tagStart := len(sealed) - gcm.Overhead()
	ciphertext := sealed[:tagStart]
	authTag := sealed[tagStart:]
	return VaultEncryptedRecord{
		Ciphertext: hex.EncodeToString(ciphertext),
		IV:         hex.EncodeToString(iv),
		AuthTag:    hex.EncodeToString(authTag),
	}, nil
}

// DecryptCredential is a pure primitive: decrypts a ciphertext bundle with
// an explicit key. Returns an error (never garbage plaintext) on auth-tag
// mismatch.
func DecryptCredential(record VaultEncryptedRecord, key []byte) (string, error) {
	ciphertext, err := hex.DecodeString(record.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("devfortress: invalid ciphertext hex: %w", err)
	}
	iv, err := hex.DecodeString(record.IV)
	if err != nil {
		return "", fmt.Errorf("devfortress: invalid iv hex: %w", err)
	}
	authTag, err := hex.DecodeString(record.AuthTag)
	if err != nil {
		return "", fmt.Errorf("devfortress: invalid auth tag hex: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("devfortress: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("devfortress: new gcm: %w", err)
	}
	sealed := append(ciphertext, authTag...)
	plaintext, err := gcm.Open(nil, iv, sealed, nil)
	if err != nil {
		return "", errors.New("devfortress: auth tag verification failed")
	}
	return string(plaintext), nil
}

// CredentialVault is a self-contained, in-memory vault: encrypts and
// stores real credentials under an alias, later resolves the alias back to
// plaintext. Used wherever a type needs its own alias-keyed encrypted
// store. Not safe for concurrent use without external locking, matching
// the Node SDK's single-threaded-per-instance assumption.
type CredentialVault struct {
	store      map[string]storedRecord
	order      []string // insertion order, for oldest-eviction
	maxEntries int
}

// NewCredentialVault returns a CredentialVault bounded at maxEntries (0
// uses the default of 50,000).
func NewCredentialVault(maxEntries int) *CredentialVault {
	if maxEntries <= 0 {
		maxEntries = maxTrackedRecords
	}
	return &CredentialVault{
		store:      make(map[string]storedRecord),
		maxEntries: maxEntries,
	}
}

// Register encrypts realCredential under key and stores it keyed by alias,
// evicting the oldest entry if the vault is at capacity.
func (v *CredentialVault) Register(alias, realCredential string, key []byte) (VaultEncryptedRecord, error) {
	record, err := EncryptCredential(realCredential, key)
	if err != nil {
		return VaultEncryptedRecord{}, err
	}
	if _, exists := v.store[alias]; exists {
		v.deleteAlias(alias)
	} else if len(v.store) >= v.maxEntries && len(v.order) > 0 {
		oldest := v.order[0]
		v.deleteAlias(oldest)
	}
	v.store[alias] = storedRecord{VaultEncryptedRecord: record, key: key}
	v.order = append(v.order, alias)
	return record, nil
}

// Resolve decrypts the credential stored under alias. Returns ("", false)
// for an unknown alias or a tampered/corrupted record — never garbage
// plaintext.
func (v *CredentialVault) Resolve(alias string) (string, bool) {
	stored, ok := v.store[alias]
	if !ok {
		return "", false
	}
	plaintext, err := DecryptCredential(stored.VaultEncryptedRecord, stored.key)
	if err != nil {
		return "", false
	}
	return plaintext, true
}

// Revoke removes alias from the vault. Reports whether it was present.
func (v *CredentialVault) Revoke(alias string) bool {
	if _, ok := v.store[alias]; !ok {
		return false
	}
	v.deleteAlias(alias)
	return true
}

// Has reports whether alias is currently registered.
func (v *CredentialVault) Has(alias string) bool {
	_, ok := v.store[alias]
	return ok
}

func (v *CredentialVault) deleteAlias(alias string) {
	delete(v.store, alias)
	for i, a := range v.order {
		if a == alias {
			v.order = append(v.order[:i], v.order[i+1:]...)
			break
		}
	}
}
