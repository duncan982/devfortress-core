package devfortress

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// ── ConfigIntegrityVerifier (Invention A9) ───────────────────────────────

// Mirrors the Node SDK's ConfigIntegrityVerifier (config-integrity-verifier.ts).
// TODO 419/426 — one of the 20 Node-only claims identified by the
// 2026-11-02 patent audit.
//
// Seals an HMAC-SHA256 digest of a configuration snapshot at
// initialization and flags drift (tampered thresholds, disabled
// features, injected configuration) when re-verified later.
//
// Node's own class also starts a periodic background timer that calls
// Verify automatically; this port deliberately does not spawn a
// goroutine for that — call Verify yourself on whatever cadence suits
// your application. The actual patented mechanism (seal, hash, compare,
// locate the specific violating fields) is unchanged.

var configIntegrityCriticalFields = []string{
	"mode", "failClosed", "tier", "apiKey", "blockThreshold", "rateLimitMax", "rateLimitWindowMs",
}

// ConfigViolation describes one field that drifted from its sealed value.
type ConfigViolation struct {
	Field     string
	Expected  string
	Actual    string
	Severity  string // "HIGH" | "CRITICAL"
	Timestamp int64
	Reason    string
}

// ConfigIntegrityResult is the outcome of a Seal/Verify/GetStatus call.
type ConfigIntegrityResult struct {
	Valid        bool
	Violations   []ConfigViolation
	LastVerified int64
	CheckCount   int
}

// ConfigIntegrityVerifier seals a config snapshot's HMAC digest and
// verifies it against drift. Safe for concurrent use.
type ConfigIntegrityVerifier struct {
	hmacSecret  []byte
	onViolation func(ConfigViolation)

	mu               sync.Mutex
	originalHash     string
	originalSnapshot map[string]any
	checkCount       int
	lastVerified     int64
	violations       []ConfigViolation
}

// NewConfigIntegrityVerifier creates a ConfigIntegrityVerifier. hmacSecret
// may be nil, in which case a random secret is generated. onViolation may
// be nil.
func NewConfigIntegrityVerifier(hmacSecret []byte, onViolation func(ConfigViolation)) *ConfigIntegrityVerifier {
	secret := hmacSecret
	if secret == nil {
		secret = make([]byte, 32)
		_, _ = rand.Read(secret)
	}
	if onViolation == nil {
		onViolation = func(ConfigViolation) {}
	}
	return &ConfigIntegrityVerifier{hmacSecret: secret, onViolation: onViolation}
}

// Seal seals the SDK configuration. Call once at initialization.
func (v *ConfigIntegrityVerifier) Seal(sdkConfig map[string]any) string {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.originalSnapshot = deepCloneMap(sdkConfig)
	v.originalHash = computeConfigHMAC(v.hmacSecret, v.originalSnapshot)
	v.lastVerified = time.Now().UnixMilli()
	v.checkCount = 0
	v.violations = nil
	return v.originalHash
}

// Verify verifies the current configuration against the sealed snapshot.
func (v *ConfigIntegrityVerifier) Verify(currentConfig map[string]any) ConfigIntegrityResult {
	v.mu.Lock()
	v.checkCount++
	v.lastVerified = time.Now().UnixMilli()

	currentHash := computeConfigHMAC(v.hmacSecret, currentConfig)
	valid := currentHash == v.originalHash

	if !valid {
		newViolations := findConfigViolations(v.originalSnapshot, currentConfig, "")
		v.violations = append(v.violations, newViolations...)
		for _, nv := range newViolations {
			v.onViolation(nv)
		}
	}

	result := ConfigIntegrityResult{
		Valid:        valid,
		Violations:   append([]ConfigViolation{}, v.violations...),
		LastVerified: v.lastVerified,
		CheckCount:   v.checkCount,
	}
	v.mu.Unlock()
	return result
}

// GetStatus returns the current integrity status without re-checking.
func (v *ConfigIntegrityVerifier) GetStatus() ConfigIntegrityResult {
	v.mu.Lock()
	defer v.mu.Unlock()
	return ConfigIntegrityResult{
		Valid:        len(v.violations) == 0,
		Violations:   append([]ConfigViolation{}, v.violations...),
		LastVerified: v.lastVerified,
		CheckCount:   v.checkCount,
	}
}

func computeConfigHMAC(secret []byte, obj map[string]any) string {
	serialized := canonicalJSON(obj)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(serialized))
	return hex.EncodeToString(mac.Sum(nil))
}

// canonicalJSON produces a deterministic JSON encoding with sorted keys,
// recursively, matching Node's JSON.stringify(obj, Object.keys(obj).sort()).
func canonicalJSON(obj map[string]any) string {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		kb, _ := json.Marshal(k)
		parts = append(parts, string(kb)+":"+canonicalValue(obj[k]))
	}
	return "{" + joinStrings(parts, ",") + "}"
}

func canonicalValue(v any) string {
	if m, ok := v.(map[string]any); ok {
		return canonicalJSON(m)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func joinStrings(parts []string, sep string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += sep
		}
		out += p
	}
	return out
}

func deepCloneMap(obj map[string]any) map[string]any {
	b, _ := json.Marshal(obj)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

func findConfigViolations(original, current map[string]any, prefix string) []ConfigViolation {
	var violations []ConfigViolation
	now := time.Now().UnixMilli()

	seen := make(map[string]bool)
	for k := range original {
		seen[k] = true
	}
	for k := range current {
		seen[k] = true
	}

	for key := range seen {
		field := key
		if prefix != "" {
			field = prefix + "." + key
		}
		origVal, origOk := original[key]
		currVal, currOk := current[key]

		origJSON, _ := json.Marshal(origVal)
		currJSON, _ := json.Marshal(currVal)
		if origOk == currOk && string(origJSON) == string(currJSON) {
			continue
		}

		severity := "HIGH"
		for _, f := range configIntegrityCriticalFields {
			if strings.Contains(field, f) {
				severity = "CRITICAL"
				break
			}
		}

		origMap, origIsMap := origVal.(map[string]any)
		currMap, currIsMap := currVal.(map[string]any)
		if origIsMap && currIsMap {
			violations = append(violations, findConfigViolations(origMap, currMap, field)...)
			continue
		}

		violations = append(violations, ConfigViolation{
			Field:     field,
			Expected:  fmt.Sprintf("%v", origVal),
			Actual:    fmt.Sprintf("%v", currVal),
			Severity:  severity,
			Timestamp: now,
			Reason:    fmt.Sprintf("Config field '%s' changed from '%v' to '%v'", field, origVal, currVal),
		})
	}

	return violations
}
