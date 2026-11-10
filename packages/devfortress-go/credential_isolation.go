package devfortress

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// CacheAdapter is a pluggable cache backend for CredentialIsolationManager
// and ThreatInterceptor. Implement this over Redis (or similar) for
// production; an in-memory fallback is used when none is supplied.
type CacheAdapter interface {
	Get(ctx context.Context, key string) (string, bool, error)
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	Del(ctx context.Context, key string) error
}

// RevocationReason is why a session alias was revoked.
type RevocationReason string

const (
	RevocationActiveThreat   RevocationReason = "active_threat"
	RevocationRotationExpired RevocationReason = "rotation_expired"
	RevocationLogout         RevocationReason = "logout"
)

// IsolatedCredentialData is what an alias resolves back to.
type IsolatedCredentialData struct {
	RealToken string
	UserID    string
	CreatedAt time.Time
}

// RevocationDetails describes a recorded revocation (audit support).
type RevocationDetails struct {
	Reason           RevocationReason
	RevokedAt        time.Time
	RevocationScope  string // "precise" or "broad"
}

const encryptedPrefix = "enc:v1:"

func isolationEncrypt(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, iv, []byte(plaintext), nil)
	tagStart := len(sealed) - gcm.Overhead()
	return encryptedPrefix + hex.EncodeToString(iv) + ":" + hex.EncodeToString(sealed[:tagStart]) + ":" + hex.EncodeToString(sealed[tagStart:]), nil
}

func isolationDecrypt(ciphertext string, key []byte) (string, error) {
	if !strings.HasPrefix(ciphertext, encryptedPrefix) {
		return ciphertext, nil // legacy unencrypted format — rolling migration
	}
	parts := strings.Split(strings.TrimPrefix(ciphertext, encryptedPrefix), ":")
	if len(parts) != 3 {
		return "", errors.New("devfortress: invalid encrypted format")
	}
	iv, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", err
	}
	enc, err := hex.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	tag, err := hex.DecodeString(parts[2])
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plaintext, err := gcm.Open(nil, iv, append(enc, tag...), nil)
	if err != nil {
		return "", errors.New("devfortress: auth tag verification failed")
	}
	return string(plaintext), nil
}

func hashToken(realToken string) string {
	return sha256Hex(realToken)
}

// lruEntry is one entry in the in-memory LRU fallback cache.
type lruEntry struct {
	value     string
	expiresAt time.Time
}

// lruCache is an in-memory LRU, used as a fallback when the configured
// CacheAdapter (e.g. Redis) is unavailable, and as the sole backend when
// none is configured at all. Not safe for concurrent use on its own; both
// callers below hold their own mutex.
type lruCache struct {
	maxEntries int
	defaultTTL time.Duration
	entries    map[string]lruEntry
	order      []string
}

func newLRUCache(maxEntries int, defaultTTL time.Duration) *lruCache {
	return &lruCache{maxEntries: maxEntries, defaultTTL: defaultTTL, entries: make(map[string]lruEntry)}
}

func (l *lruCache) get(key string) (string, bool) {
	entry, ok := l.entries[key]
	if !ok {
		return "", false
	}
	if time.Now().After(entry.expiresAt) {
		l.delete(key)
		return "", false
	}
	return entry.value, true
}

func (l *lruCache) set(key, value string, ttl time.Duration) {
	if ttl <= 0 {
		ttl = l.defaultTTL
	}
	if _, exists := l.entries[key]; !exists && len(l.entries) >= l.maxEntries && len(l.order) > 0 {
		oldest := l.order[0]
		l.delete(oldest)
	}
	if _, exists := l.entries[key]; !exists {
		l.order = append(l.order, key)
	}
	l.entries[key] = lruEntry{value: value, expiresAt: time.Now().Add(ttl)}
}

func (l *lruCache) delete(key string) {
	delete(l.entries, key)
	for i, k := range l.order {
		if k == key {
			l.order = append(l.order[:i], l.order[i+1:]...)
			break
		}
	}
}

func (l *lruCache) has(key string) bool {
	_, ok := l.get(key)
	return ok
}

// memoryCacheAdapter is the in-memory CacheAdapter used when no production
// backend is configured.
type memoryCacheAdapter struct {
	mu      sync.Mutex
	entries map[string]lruEntry
}

func newMemoryCacheAdapter() *memoryCacheAdapter {
	return &memoryCacheAdapter{entries: make(map[string]lruEntry)}
}

func (m *memoryCacheAdapter) Get(_ context.Context, key string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.entries[key]
	if !ok || time.Now().After(entry.expiresAt) {
		delete(m.entries, key)
		return "", false, nil
	}
	return entry.value, true, nil
}

func (m *memoryCacheAdapter) Set(_ context.Context, key, value string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[key] = lruEntry{value: value, expiresAt: time.Now().Add(ttl)}
	return nil
}

func (m *memoryCacheAdapter) Del(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, key)
	return nil
}

// ThreatInterceptor is a local emergency blocklist: synchronous,
// pre-webhook IP blocking. When a critical event fires, the IP is written
// here before any webhook is sent, so it is blocked even if the webhook
// receiver is unreachable.
type ThreatInterceptor struct {
	mu             sync.Mutex
	cache          CacheAdapter
	lru            *lruCache
	defaultTTL     time.Duration
}

// NewThreatInterceptor returns a ThreatInterceptor. cache may be nil (an
// in-memory fallback is used). ttl defaults to 15 minutes (a 10-minute
// webhook retry window plus a 5-minute safety margin) when zero.
func NewThreatInterceptor(cache CacheAdapter, ttl time.Duration) *ThreatInterceptor {
	if cache == nil {
		cache = newMemoryCacheAdapter()
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return &ThreatInterceptor{cache: cache, lru: newLRUCache(5000, ttl), defaultTTL: ttl}
}

// BlockIP blocks ip immediately. reason defaults to "critical_event".
func (t *ThreatInterceptor) BlockIP(ctx context.Context, ip, reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if reason == "" {
		reason = "critical_event"
	}
	value, _ := json.Marshal(map[string]any{"reason": reason, "blockedAt": time.Now().UnixMilli()})
	t.lru.set("emergency:block:"+ip, string(value), t.defaultTTL)
	_ = t.cache.Set(ctx, "emergency:block:"+ip, string(value), t.defaultTTL) // Redis failure doesn't prevent blocking
}

// IsBlocked reports whether ip is emergency-blocked. O(1) on the LRU fast
// path — safe to call on every request.
func (t *ThreatInterceptor) IsBlocked(ctx context.Context, ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.lru.has("emergency:block:" + ip) {
		return true
	}
	val, ok, err := t.cache.Get(ctx, "emergency:block:"+ip)
	if err != nil {
		return false // on cache failure, the LRU check above was already authoritative
	}
	return ok && val != ""
}

// UnblockIP removes ip from the emergency blocklist.
func (t *ThreatInterceptor) UnblockIP(ctx context.Context, ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lru.delete("emergency:block:" + ip)
	_ = t.cache.Del(ctx, "emergency:block:"+ip)
}

// CredentialIsolationManagerConfig configures a CredentialIsolationManager.
type CredentialIsolationManagerConfig struct {
	// EncryptionKey is a 32-byte hex string (64 hex characters) for
	// AES-256-GCM encryption of forward-mapping values. Required — see
	// NewCredentialIsolationManager.
	EncryptionKey string
	// LRUMaxEntries bounds the in-memory fallback cache. Default: 1000.
	LRUMaxEntries int
	// LRUTTL is the fallback cache's entry lifetime. Default: 60s.
	LRUTTL time.Duration
	// RotationGracePeriod is how long a rotated alias stays resolvable for
	// revocation. Default: 20 minutes.
	RotationGracePeriod time.Duration
	// OnFallbackRevocation is called with the user ID when alias
	// resolution fails during revocation, so the caller can perform a
	// broad, subject-level session revocation instead.
	OnFallbackRevocation func(ctx context.Context, userID, reason string)
}

// CredentialIsolationManager replaces real session tokens with opaque,
// random aliases before they leave the trust boundary: DevFortress only
// ever sees the alias, never the real token. Hardened: AES-256-GCM
// encryption of forward-mapping values, SHA-256 hashed reverse-mapping
// keys, subject-level fallback revocation on cache failure, a rotation
// grace period, and an in-memory LRU fallback that survives cache outages.
type CredentialIsolationManager struct {
	mu                   sync.Mutex
	cache                CacheAdapter
	encryptionKey        []byte
	lru                  *lruCache
	rotationGracePeriod  time.Duration
	onFallbackRevocation func(ctx context.Context, userID, reason string)
}

// NewCredentialIsolationManager returns a manager. cache may be nil (an
// in-memory fallback is used). EncryptionKey is mandatory: encryption is
// not optional, so construction fails loudly rather than silently storing
// credentials in plaintext.
func NewCredentialIsolationManager(cache CacheAdapter, cfg CredentialIsolationManagerConfig) (*CredentialIsolationManager, error) {
	if cfg.EncryptionKey == "" {
		return nil, errors.New("devfortress: EncryptionKey is required — CredentialIsolationManager refuses to store credentials without encryption; set it to a 32-byte hex string (64 hex characters), e.g. from `openssl rand -hex 32`")
	}
	key, err := hex.DecodeString(cfg.EncryptionKey)
	if err != nil || len(key) != 32 {
		return nil, errors.New("devfortress: EncryptionKey must be a 32-byte hex string (64 hex characters)")
	}
	if cache == nil {
		cache = newMemoryCacheAdapter()
	}
	lruMax := cfg.LRUMaxEntries
	if lruMax <= 0 {
		lruMax = 1000
	}
	lruTTL := cfg.LRUTTL
	if lruTTL <= 0 {
		lruTTL = 60 * time.Second
	}
	grace := cfg.RotationGracePeriod
	if grace <= 0 {
		grace = 20 * time.Minute
	}
	return &CredentialIsolationManager{
		cache: cache, encryptionKey: key, lru: newLRUCache(lruMax, lruTTL),
		rotationGracePeriod: grace, onFallbackRevocation: cfg.OnFallbackRevocation,
	}, nil
}

func (m *CredentialIsolationManager) cacheGet(ctx context.Context, key string) (string, bool) {
	val, ok, err := m.cache.Get(ctx, key)
	if err == nil && ok {
		m.lru.set(key, val, 0)
		return val, true
	}
	return m.lru.get(key)
}

func (m *CredentialIsolationManager) cacheSet(ctx context.Context, key, value string, ttl time.Duration) {
	m.lru.set(key, value, ttl)
	_ = m.cache.Set(ctx, key, value, ttl) // LRU already set — cache failure is survivable
}

func (m *CredentialIsolationManager) cacheDel(ctx context.Context, key string) {
	m.lru.delete(key)
	_ = m.cache.Del(ctx, key)
}

// CreateAlias generates a cryptographically random alias for a real
// session token (no mathematical relationship to the token). Writes both
// the forward mapping (encrypted) and a hashed reverse-lookup entry.
func (m *CredentialIsolationManager) CreateAlias(ctx context.Context, realToken, userID string, ttl time.Duration) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.createAliasLocked(ctx, realToken, userID, ttl)
}

func (m *CredentialIsolationManager) createAliasLocked(ctx context.Context, realToken, userID string, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = time.Hour
	}
	tokenHash := hashToken(realToken)

	if existing, ok := m.cacheGet(ctx, "cred:alias:"+tokenHash); ok {
		return existing, nil
	}

	alias := "df_sid_" + randomHex(16)
	data := IsolatedCredentialData{RealToken: realToken, UserID: userID, CreatedAt: time.Now()}
	raw, err := json.Marshal(map[string]any{
		"realToken": data.RealToken, "userId": data.UserID, "createdAt": data.CreatedAt.UnixMilli(),
	})
	if err != nil {
		return "", err
	}
	encrypted, err := isolationEncrypt(string(raw), m.encryptionKey)
	if err != nil {
		return "", err
	}

	m.cacheSet(ctx, "alias:"+alias, encrypted, ttl)
	m.cacheSet(ctx, "cred:alias:"+tokenHash, alias, ttl)
	return alias, nil
}

// ResolveAlias resolves alias back to the real token and user. Intended
// to be called only when a revocation command arrives. Returns
// (zero-value, false) for an unknown alias.
func (m *CredentialIsolationManager) ResolveAlias(ctx context.Context, alias string) (IsolatedCredentialData, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.resolveAliasLocked(ctx, alias)
}

func (m *CredentialIsolationManager) resolveAliasLocked(ctx context.Context, alias string) (IsolatedCredentialData, bool) {
	raw, ok := m.cacheGet(ctx, "alias:"+alias)
	if !ok {
		return IsolatedCredentialData{}, false
	}
	decrypted, err := isolationDecrypt(raw, m.encryptionKey)
	if err != nil {
		return IsolatedCredentialData{}, false
	}
	var parsed struct {
		RealToken string `json:"realToken"`
		UserID    string `json:"userId"`
		CreatedAt int64  `json:"createdAt"`
	}
	if err := json.Unmarshal([]byte(decrypted), &parsed); err != nil {
		return IsolatedCredentialData{}, false
	}
	return IsolatedCredentialData{
		RealToken: parsed.RealToken, UserID: parsed.UserID,
		CreatedAt: time.UnixMilli(parsed.CreatedAt),
	}, true
}

// RevokeByAlias revokes a session by alias, returning the resolved token
// data so the caller can perform the actual session revocation (the real
// token never leaves the caller). On cache failure, or when alias
// resolution itself fails, falls back to calling OnFallbackRevocation with
// subjectID for a broad, subject-level revocation.
func (m *CredentialIsolationManager) RevokeByAlias(ctx context.Context, alias string, reason RevocationReason, subjectID string) (IsolatedCredentialData, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if reason == "" {
		reason = RevocationActiveThreat
	}

	resolved, ok := m.resolveAliasLocked(ctx, alias)
	if !ok {
		if subjectID != "" && m.onFallbackRevocation != nil {
			m.onFallbackRevocation(ctx, subjectID, fmt.Sprintf("[DF] alias resolution failed for %s — falling back to subjectId revocation", alias))
		}
		return IsolatedCredentialData{}, false
	}

	tokenHash := hashToken(resolved.RealToken)
	m.cacheDel(ctx, "alias:"+alias)
	m.cacheDel(ctx, "cred:alias:"+tokenHash)

	marker, _ := json.Marshal(map[string]any{
		"revoked": true, "reason": reason, "revokedAt": time.Now().UnixMilli(), "revocation_scope": "precise",
	})
	m.cacheSet(ctx, "revoked:alias:"+alias, string(marker), 24*time.Hour)

	return resolved, true
}

// RotateAlias replaces the alias for a live session, limiting the window
// of exposure if an alias is somehow observed in transit. The old alias is
// not deleted immediately — it gets a grace-period TTL and remains
// resolvable for revocation purposes.
func (m *CredentialIsolationManager) RotateAlias(ctx context.Context, oldAlias string, ttl time.Duration) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	resolved, ok := m.resolveAliasLocked(ctx, oldAlias)
	if !ok {
		return "", false, nil
	}

	raw, _ := json.Marshal(map[string]any{
		"realToken": resolved.RealToken, "userId": resolved.UserID, "createdAt": resolved.CreatedAt.UnixMilli(),
		"status": "rotating", "canCreateNewEvents": false,
	})
	encrypted, err := isolationEncrypt(string(raw), m.encryptionKey)
	if err != nil {
		return "", false, err
	}
	m.cacheSet(ctx, "alias:"+oldAlias, encrypted, m.rotationGracePeriod)

	tokenHash := hashToken(resolved.RealToken)
	m.cacheDel(ctx, "cred:alias:"+tokenHash)

	newAlias, err := m.createAliasLocked(ctx, resolved.RealToken, resolved.UserID, ttl)
	if err != nil {
		return "", false, err
	}
	return newAlias, true, nil
}

// RevokeOnLogout cleans up the alias for a real token immediately, rather
// than waiting for TTL expiry. Always call this on logout.
func (m *CredentialIsolationManager) RevokeOnLogout(ctx context.Context, realToken string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	tokenHash := hashToken(realToken)
	alias, ok := m.cacheGet(ctx, "cred:alias:"+tokenHash)
	if !ok {
		return
	}

	marker, _ := json.Marshal(map[string]any{
		"revoked": true, "reason": RevocationLogout, "revokedAt": time.Now().UnixMilli(), "revocation_scope": "precise",
	})
	m.cacheSet(ctx, "revoked:alias:"+alias, string(marker), 24*time.Hour)
	m.cacheDel(ctx, "alias:"+alias)
	m.cacheDel(ctx, "cred:alias:"+tokenHash)
}

// IsRevoked reports whether alias was already revoked (idempotency for
// repeated revocation deliveries).
func (m *CredentialIsolationManager) IsRevoked(ctx context.Context, alias string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.cacheGet(ctx, "revoked:alias:"+alias)
	return ok
}

// GetRevocationDetails returns the recorded revocation details for alias,
// if any.
func (m *CredentialIsolationManager) GetRevocationDetails(ctx context.Context, alias string) (RevocationDetails, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	raw, ok := m.cacheGet(ctx, "revoked:alias:"+alias)
	if !ok {
		return RevocationDetails{}, false
	}
	var parsed struct {
		Reason          string `json:"reason"`
		RevokedAt       int64  `json:"revokedAt"`
		RevocationScope string `json:"revocation_scope"`
	}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return RevocationDetails{Reason: RevocationActiveThreat, RevokedAt: time.Now(), RevocationScope: "precise"}, true
	}
	return RevocationDetails{
		Reason: RevocationReason(parsed.Reason), RevokedAt: time.UnixMilli(parsed.RevokedAt),
		RevocationScope: parsed.RevocationScope,
	}, true
}
