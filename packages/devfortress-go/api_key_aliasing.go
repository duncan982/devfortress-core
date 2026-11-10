package devfortress

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// AliasWorkload identifies the kind of workload an API key alias is scoped
// to.
type AliasWorkload string

const (
	WorkloadCI      AliasWorkload = "ci"
	WorkloadAgent   AliasWorkload = "agent"
	WorkloadPlugin  AliasWorkload = "plugin"
	WorkloadBrowser AliasWorkload = "browser"
	WorkloadServer  AliasWorkload = "server"
	WorkloadCustom  AliasWorkload = "custom"
)

// AliasState is an alias's lifecycle state.
type AliasState string

const (
	AliasActive   AliasState = "active"
	AliasRotating AliasState = "rotating"
	AliasRevoked  AliasState = "revoked"
	AliasExpired  AliasState = "expired"
)

// AliasConfig configures an APIKeyAliasingService.
type AliasConfig struct {
	// MaxAliasesPerKey is the maximum aliases per primary key. Default: 50.
	MaxAliasesPerKey int
	// RotationOverlapMs is the alias rotation overlap window. Default: 5 minutes.
	RotationOverlap time.Duration
	// AnomalyDetection enables creation-burst and fingerprint-mismatch
	// detection. Default: true.
	AnomalyDetection bool
	// CreationBurstThreshold is the alias-creation burst limit per hour. Default: 10.
	CreationBurstThreshold int
	// VaultSecret derives the forward-map's AES-256-GCM vault key (HKDF).
	// If empty, a random per-instance key is generated: Resolve keeps
	// working for the lifetime of this service instance, but not across
	// process restarts.
	VaultSecret string
	Debug       bool
}

// AliasRecord describes one issued alias. AliasKey is always "[REDACTED]"
// outside of the moment it is first created or rotated.
type AliasRecord struct {
	AliasID       string
	AliasKey      string
	PrimaryKeyHash string
	Workload      AliasWorkload
	Label         string
	State         AliasState
	Fingerprint   string
	Scope         []string
	CreatedAt     time.Time
	ExpiresAt     *time.Time
	LastUsedAt    time.Time
	RotatedFromID string
	RotatedToID   string
	UsageCount    int
}

// AliasAuditEvent is one entry in the aliasing audit log.
type AliasAuditEvent struct {
	Type           string
	AliasID        string
	PrimaryKeyHash string
	Workload       AliasWorkload
	Timestamp      time.Time
	Metadata       map[string]any
}

// AliasCreationResult is the outcome of CreateAlias.
type AliasCreationResult struct {
	Success  bool
	Alias    *AliasRecord
	AliasKey string // only populated on success
	Error    string
}

// AliasRotationResult is the outcome of RotateAlias.
type AliasRotationResult struct {
	Success          bool
	OldAliasID       string
	NewAlias         *AliasRecord
	NewAliasKey      string
	OverlapExpiresAt time.Time
	Error            string
}

// AliasValidationResult is the outcome of ValidateAliasKey.
type AliasValidationResult struct {
	Valid           bool
	AliasID         string
	Workload        AliasWorkload
	PrimaryKeyHash  string
	Reason          string
	AnomalyDetected bool
}

// AliasStats summarizes the current alias population.
type AliasStats struct {
	TotalAliases    int
	ActiveAliases   int
	RotatingAliases int
	RevokedAliases  int
	ByWorkload      map[AliasWorkload]int
	RecentAnomalies int
}

// AliasCreateOptions are optional parameters to CreateAlias.
type AliasCreateOptions struct {
	Fingerprint string
	Scope       []string
	ExpiresIn   time.Duration
}

// APIKeyAliasingService provides alias lifecycle management for API keys:
// create, rotate, revoke, inspect and audit (Invention A19). Each alias is
// scoped to a workload with fingerprint and scope binding. Not safe for
// concurrent use without external locking beyond what's documented: all
// public methods take an internal mutex.
type APIKeyAliasingService struct {
	mu sync.Mutex

	config AliasConfig

	aliases           map[string]*AliasRecord   // aliasID -> record
	aliasKeyIndex     map[string]string         // sha256(aliasKey) -> aliasID
	primaryKeyAliases map[string]map[string]bool // primaryKeyHash -> set of aliasID
	auditLog          []AliasAuditEvent
	creationTimes     []time.Time
	vaultKey          []byte
}

// NewAPIKeyAliasingService returns a service with cfg's values, applying
// documented defaults for zero fields.
func NewAPIKeyAliasingService(cfg AliasConfig) (*APIKeyAliasingService, error) {
	if cfg.MaxAliasesPerKey == 0 {
		cfg.MaxAliasesPerKey = 50
	}
	if cfg.RotationOverlap == 0 {
		cfg.RotationOverlap = 5 * time.Minute
	}
	if cfg.CreationBurstThreshold == 0 {
		cfg.CreationBurstThreshold = 10
	}

	var vaultKey []byte
	if cfg.VaultSecret != "" {
		key, err := DeriveVaultKey(cfg.VaultSecret, "api-key-aliasing")
		if err != nil {
			return nil, err
		}
		vaultKey = key
	} else {
		vaultKey = make([]byte, 32)
		if _, err := rand.Read(vaultKey); err != nil {
			return nil, fmt.Errorf("devfortress: generate vault key: %w", err)
		}
	}

	return &APIKeyAliasingService{
		config:            cfg,
		aliases:           make(map[string]*AliasRecord),
		aliasKeyIndex:     make(map[string]string),
		primaryKeyAliases: make(map[string]map[string]bool),
		vaultKey:          vaultKey,
	}, nil
}

// CreateAlias creates a new alias for a primary API key (identified only
// by its hash — the real primary key is never seen by this service).
func (s *APIKeyAliasingService) CreateAlias(primaryKeyHash string, workload AliasWorkload, label string, opts AliasCreateOptions) AliasCreationResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.createAliasLocked(primaryKeyHash, workload, label, opts)
}

func (s *APIKeyAliasingService) createAliasLocked(primaryKeyHash string, workload AliasWorkload, label string, opts AliasCreateOptions) AliasCreationResult {
	now := time.Now()

	if existing := s.primaryKeyAliases[primaryKeyHash]; existing != nil && len(existing) >= s.config.MaxAliasesPerKey {
		return AliasCreationResult{Error: fmt.Sprintf("Maximum aliases (%d) reached for this key", s.config.MaxAliasesPerKey)}
	}

	if s.config.AnomalyDetection {
		s.creationTimes = append(s.creationTimes, now)
		cutoff := now.Add(-time.Hour)
		recent := 0
		for _, t := range s.creationTimes {
			if t.After(cutoff) {
				recent++
			}
		}
		if recent > s.config.CreationBurstThreshold {
			s.emitAuditLocked(AliasAuditEvent{
				Type: "alias_misuse_detected", AliasID: "N/A", PrimaryKeyHash: primaryKeyHash,
				Workload: workload, Timestamp: now,
				Metadata: map[string]any{"reason": "creation_burst", "count": recent},
			})
			return AliasCreationResult{Error: fmt.Sprintf("Alias creation burst detected: %d in 1 hour", recent)}
		}
	}

	aliasID := "alias_" + randomHex(16)
	aliasKey := "vx_alias_" + randomHex(24)
	aliasKeyHash := sha256Hex(aliasKey)

	encryptedAliasKey, err := s.encryptAliasKey(aliasKey, primaryKeyHash)
	if err != nil {
		return AliasCreationResult{Error: err.Error()}
	}

	record := &AliasRecord{
		AliasID: aliasID, AliasKey: encryptedAliasKey, PrimaryKeyHash: primaryKeyHash,
		Workload: workload, Label: label, State: AliasActive,
		Fingerprint: opts.Fingerprint, Scope: opts.Scope,
		CreatedAt: now, LastUsedAt: now,
	}
	if opts.ExpiresIn > 0 {
		exp := now.Add(opts.ExpiresIn)
		record.ExpiresAt = &exp
	}

	s.aliases[aliasID] = record
	s.aliasKeyIndex[aliasKeyHash] = aliasID
	if s.primaryKeyAliases[primaryKeyHash] == nil {
		s.primaryKeyAliases[primaryKeyHash] = make(map[string]bool)
	}
	s.primaryKeyAliases[primaryKeyHash][aliasID] = true

	s.emitAuditLocked(AliasAuditEvent{
		Type: "alias_created", AliasID: aliasID, PrimaryKeyHash: primaryKeyHash,
		Workload: workload, Timestamp: now,
		Metadata: map[string]any{"label": label, "hasFingerprint": opts.Fingerprint != "", "scope": opts.Scope},
	})

	redacted := *record
	redacted.AliasKey = "[REDACTED]"
	return AliasCreationResult{Success: true, Alias: &redacted, AliasKey: aliasKey}
}

// RotateAlias rotates an alias with a zero-downtime overlap window: the
// old alias is marked "rotating" with a grace-period expiry rather than
// deleted immediately.
func (s *APIKeyAliasingService) RotateAlias(aliasID string) AliasRotationResult {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	oldAlias, ok := s.aliases[aliasID]
	if !ok || oldAlias.State != AliasActive {
		return AliasRotationResult{Error: fmt.Sprintf("Alias %s not found or not active", aliasID)}
	}

	oldAlias.State = AliasRotating
	expires := now.Add(s.config.RotationOverlap)
	oldAlias.ExpiresAt = &expires

	result := s.createAliasLocked(oldAlias.PrimaryKeyHash, oldAlias.Workload, oldAlias.Label+" (rotated)", AliasCreateOptions{
		Fingerprint: oldAlias.Fingerprint, Scope: oldAlias.Scope,
	})
	if !result.Success || result.Alias == nil {
		oldAlias.State = AliasActive // rollback
		return AliasRotationResult{Error: result.Error}
	}

	oldAlias.RotatedToID = result.Alias.AliasID
	// result.Alias is a redacted copy; set lineage on the real stored record too.
	if real, ok := s.aliases[result.Alias.AliasID]; ok {
		real.RotatedFromID = aliasID
	}

	s.emitAuditLocked(AliasAuditEvent{
		Type: "alias_rotated", AliasID: aliasID, PrimaryKeyHash: oldAlias.PrimaryKeyHash,
		Workload: oldAlias.Workload, Timestamp: now,
		Metadata: map[string]any{"newAliasId": result.Alias.AliasID, "overlap": s.config.RotationOverlap.String()},
	})

	return AliasRotationResult{
		Success: true, OldAliasID: aliasID, NewAlias: result.Alias,
		NewAliasKey: result.AliasKey, OverlapExpiresAt: expires,
	}
}

// RevokeAlias revokes a specific alias without affecting any other alias
// on the same primary key. reason defaults to "manual_revocation".
func (s *APIKeyAliasingService) RevokeAlias(aliasID, reason string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	alias, ok := s.aliases[aliasID]
	if !ok {
		return false
	}
	alias.State = AliasRevoked
	if reason == "" {
		reason = "manual_revocation"
	}
	s.emitAuditLocked(AliasAuditEvent{
		Type: "alias_revoked", AliasID: aliasID, PrimaryKeyHash: alias.PrimaryKeyHash,
		Workload: alias.Workload, Timestamp: time.Now(),
		Metadata: map[string]any{"reason": reason},
	})
	return true
}

// ValidateAliasKey validates an alias key presented on an incoming
// request, optionally checking it against an observed fingerprint.
func (s *APIKeyAliasingService) ValidateAliasKey(aliasKey, fingerprint string) AliasValidationResult {
	s.mu.Lock()
	defer s.mu.Unlock()

	aliasKeyHash := sha256Hex(aliasKey)
	aliasID, ok := s.aliasKeyIndex[aliasKeyHash]
	if !ok {
		return AliasValidationResult{Reason: "Unknown alias key"}
	}
	alias, ok := s.aliases[aliasID]
	if !ok {
		return AliasValidationResult{Reason: "Alias record not found"}
	}

	now := time.Now()

	if alias.State == AliasRevoked {
		return AliasValidationResult{AliasID: aliasID, Workload: alias.Workload, Reason: "Alias has been revoked"}
	}

	if alias.ExpiresAt != nil && now.After(*alias.ExpiresAt) {
		alias.State = AliasExpired
		s.emitAuditLocked(AliasAuditEvent{
			Type: "alias_expired", AliasID: aliasID, PrimaryKeyHash: alias.PrimaryKeyHash,
			Workload: alias.Workload, Timestamp: now,
		})
		return AliasValidationResult{AliasID: aliasID, Workload: alias.Workload, Reason: "Alias has expired"}
	}

	anomaly := false
	if alias.Fingerprint != "" && fingerprint != "" && alias.Fingerprint != fingerprint {
		anomaly = true
		expected := alias.Fingerprint
		if len(expected) > 8 {
			expected = expected[:8]
		}
		s.emitAuditLocked(AliasAuditEvent{
			Type: "alias_misuse_detected", AliasID: aliasID, PrimaryKeyHash: alias.PrimaryKeyHash,
			Workload: alias.Workload, Timestamp: now,
			Metadata: map[string]any{"reason": "fingerprint_mismatch", "expectedFingerprint": expected},
		})
	}

	alias.LastUsedAt = now
	alias.UsageCount++

	s.emitAuditLocked(AliasAuditEvent{
		Type: "alias_used", AliasID: aliasID, PrimaryKeyHash: alias.PrimaryKeyHash,
		Workload: alias.Workload, Timestamp: now,
	})

	reason := "Valid alias"
	if anomaly {
		reason = "Fingerprint mismatch detected"
	}
	return AliasValidationResult{
		Valid: !anomaly, AliasID: aliasID, Workload: alias.Workload,
		PrimaryKeyHash: alias.PrimaryKeyHash, Reason: reason, AnomalyDetected: anomaly,
	}
}

// ListAliases returns every alias (with AliasKey redacted) issued for a
// primary key.
func (s *APIKeyAliasingService) ListAliases(primaryKeyHash string) []AliasRecord {
	s.mu.Lock()
	defer s.mu.Unlock()

	ids := s.primaryKeyAliases[primaryKeyHash]
	out := make([]AliasRecord, 0, len(ids))
	for id := range ids {
		if a, ok := s.aliases[id]; ok {
			redacted := *a
			redacted.AliasKey = "[REDACTED]"
			out = append(out, redacted)
		}
	}
	return out
}

// Stats returns a snapshot of alias population and recent-anomaly counts.
func (s *APIKeyAliasingService) Stats() AliasStats {
	s.mu.Lock()
	defer s.mu.Unlock()

	stats := AliasStats{ByWorkload: make(map[AliasWorkload]int)}
	stats.TotalAliases = len(s.aliases)
	for _, a := range s.aliases {
		switch a.State {
		case AliasActive:
			stats.ActiveAliases++
		case AliasRotating:
			stats.RotatingAliases++
		case AliasRevoked:
			stats.RevokedAliases++
		}
		stats.ByWorkload[a.Workload]++
	}
	cutoff := time.Now().Add(-time.Hour)
	for _, e := range s.auditLog {
		if e.Type == "alias_misuse_detected" && e.Timestamp.After(cutoff) {
			stats.RecentAnomalies++
		}
	}
	return stats
}

// AuditLog returns up to limit of the most recent audit events.
func (s *APIKeyAliasingService) AuditLog(limit int) []AliasAuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > len(s.auditLog) {
		limit = len(s.auditLog)
	}
	start := len(s.auditLog) - limit
	out := make([]AliasAuditEvent, limit)
	copy(out, s.auditLog[start:])
	return out
}

// Resolve resolves a stored alias back to its real alias key. Returns
// ("", false) for an unknown/revoked/expired alias, or if the stored
// ciphertext fails auth-tag verification.
func (s *APIKeyAliasingService) Resolve(aliasID string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	alias, ok := s.aliases[aliasID]
	if !ok || alias.State == AliasRevoked || alias.State == AliasExpired {
		return "", false
	}

	var record VaultEncryptedRecord
	if err := json.Unmarshal([]byte(alias.AliasKey), &record); err != nil {
		return "", false
	}
	decrypted, err := DecryptCredential(record, s.vaultKey)
	if err != nil {
		return "", false
	}
	if idx := strings.Index(decrypted, ":"); idx != -1 {
		return decrypted[idx+1:], true
	}
	return decrypted, true
}

func (s *APIKeyAliasingService) encryptAliasKey(aliasKey, primaryKeyHash string) (string, error) {
	record, err := EncryptCredential(primaryKeyHash+":"+aliasKey, s.vaultKey)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func (s *APIKeyAliasingService) emitAuditLocked(event AliasAuditEvent) {
	s.auditLog = append(s.auditLog, event)
	if len(s.auditLog) > 10_000 {
		s.auditLog = s.auditLog[len(s.auditLog)-10_000:]
	}
}

func randomHex(bytes int) string {
	buf := make([]byte, bytes)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
