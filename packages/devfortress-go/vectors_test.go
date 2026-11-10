package devfortress

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// loadVectors reads a shared cross-language vector file from the
// repository's contracts/ directory (../../contracts from this package),
// or from DEVFORTRESS_CONTRACTS_DIR when set.
func loadVectors(t *testing.T, file string) map[string]any {
	t.Helper()
	dir := os.Getenv("DEVFORTRESS_CONTRACTS_DIR")
	if dir == "" {
		dir = filepath.Join("..", "..", "contracts")
	}
	path := filepath.Join(dir, file)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("shared vector file not found: %s (set DEVFORTRESS_CONTRACTS_DIR): %v", path, err)
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatalf("unexpected vector file shape: %s: %v", file, err)
	}
	return data
}

func section(t *testing.T, vectors map[string]any, name string) []any {
	t.Helper()
	v, ok := vectors[name].([]any)
	if !ok {
		t.Fatalf("vectors section %q is not a list", name)
	}
	return v
}

func asMap(t *testing.T, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("vector entry is not an object: %#v", v)
	}
	return m
}

func str(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

// strOrNil returns the header's string value, or "" when it is JSON null or
// absent (matching how our SignedHeaders/Verify treat a missing header).
func strOrNil(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

func num(m map[string]any, key string) int64 {
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	}
	return 0
}

func wireHeaders(t *testing.T, v map[string]any) map[string]string {
	t.Helper()
	h := asMap(t, v["headers"])
	return map[string]string{
		NonceHeader:       strOrNil(h, "nonce"),
		TimestampHeader:   strOrNil(h, "timestamp"),
		PayloadHashHeader: strOrNil(h, "payload_hash"),
		SignatureHeader:   strOrNil(h, "signature"),
		VersionHeader:     strOrNil(h, "version"),
	}
}
