package devfortress

import (
	"regexp"
	"strings"
	"testing"
)

// The shared cross-language vectors (contracts/ingest-signature-vectors.json):
// the platform, the Node SDK, the Python SDK, the PHP SDK and the open-core
// route all assert the same file.

func TestEveryVerifierVectorGivesItsExpectedResult(t *testing.T) {
	vectors := loadVectors(t, "ingest-signature-vectors.json")
	list := section(t, vectors, "vectors")
	if len(list) < 26 {
		t.Fatalf("expected at least 26 vectors, got %d", len(list))
	}
	for _, raw := range list {
		v := asMap(t, raw)
		got := Verify(str(v, "verify_key"), str(v, "method"), str(v, "request_target"), str(v, "body"), wireHeaders(t, v), num(v, "now_ms"))
		want := str(v, "expected")
		if string(got) != want {
			t.Errorf("%s: got %q, want %q", str(v, "name"), got, want)
		}
	}
}

func TestSigningMatchesTheVectorsByteForByte(t *testing.T) {
	vectors := loadVectors(t, "ingest-signature-vectors.json")
	list := section(t, vectors, "vectors")
	checked := 0
	for _, raw := range list {
		v := asMap(t, raw)
		expected := str(v, "expected")
		if v["sign_input"] == nil || (expected != "valid" && expected != "expired") {
			continue
		}
		in := asMap(t, v["sign_input"])
		signer, err := NewSigner(str(in, "api_key"))
		if err != nil {
			t.Fatalf("%s: %v", str(v, "name"), err)
		}
		signed, err := signer.Sign(str(in, "method"), str(in, "request_target"), str(in, "body"), str(in, "timestamp"), str(in, "nonce"))
		if err != nil {
			t.Fatalf("%s: %v", str(v, "name"), err)
		}
		want := wireHeaders(t, v)
		name := str(v, "name")
		if strings.ToLower(want[PayloadHashHeader]) != signed[PayloadHashHeader] {
			t.Errorf("%s: payload hash mismatch", name)
		}
		if strings.ToLower(want[SignatureHeader]) != signed[SignatureHeader] {
			t.Errorf("%s: signature mismatch", name)
		}
		if want[NonceHeader] != signed[NonceHeader] {
			t.Errorf("%s: nonce mismatch", name)
		}
		if want[TimestampHeader] != signed[TimestampHeader] {
			t.Errorf("%s: timestamp mismatch", name)
		}
		if signed[VersionHeader] != "2" {
			t.Errorf("%s: version mismatch", name)
		}
		checked++
	}
	if checked < 8 {
		t.Fatalf("expected at least 8 signed vectors checked, got %d", checked)
	}
}

func TestNegativeVectorsDoNotMatchWhatTheSignerProduces(t *testing.T) {
	// A signature made for one request must not equal the signature of the
	// request the server actually received (other path, method, query, ...).
	names := map[string]bool{
		"different_path": true, "different_path_same_query": true, "different_method": true,
		"changed_query": true, "query_added": true, "prefix_stripped": true,
		"tampered_body": true, "wrong_key": true,
	}
	vectors := loadVectors(t, "ingest-signature-vectors.json")
	list := section(t, vectors, "vectors")
	seen := 0
	for _, raw := range list {
		v := asMap(t, raw)
		name := str(v, "name")
		if !names[name] {
			continue
		}
		seen++
		wire := wireHeaders(t, v)
		signer, err := NewSigner(str(v, "verify_key"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		signed, err := signer.Sign(str(v, "method"), str(v, "request_target"), str(v, "body"), wire[TimestampHeader], wire[NonceHeader])
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if wire[SignatureHeader] == signed[SignatureHeader] {
			t.Errorf("%s: signature unexpectedly matched", name)
		}
	}
	if seen != len(names) {
		t.Fatalf("expected to see %d negative vectors, saw %d", len(names), seen)
	}
}

func TestKeyIDDerivationMatchesTheVectors(t *testing.T) {
	vectors := loadVectors(t, "ingest-signature-vectors.json")
	derivation := asMap(t, vectors["key_id_derivation"])
	list, ok := derivation["vectors"].([]any)
	if !ok || len(list) < 3 {
		t.Fatalf("expected at least 3 key_id_derivation vectors")
	}
	for _, raw := range list {
		v := asMap(t, raw)
		apiKey := str(v, "api_key")
		want := str(v, "key_id")
		if got := DeriveKeyID(apiKey); got != want {
			t.Errorf("DeriveKeyID(%q) = %q, want %q", apiKey, got, want)
		}
		signer, err := NewSigner(apiKey)
		if err != nil {
			t.Fatal(err)
		}
		if got := signer.KeyID(); got != want {
			t.Errorf("KeyID() = %q, want %q", got, want)
		}
	}
}

func TestSignedPathVectorHeadersMatchByteForByte(t *testing.T) {
	vectors := loadVectors(t, "ingest-signature-vectors.json")
	list := section(t, vectors, "signed_path_vectors")
	checked := 0
	for _, raw := range list {
		v := asMap(t, raw)
		if v["sign_input"] == nil {
			continue
		}
		in := asMap(t, v["sign_input"])
		signer, err := NewSigner(str(in, "api_key"))
		if err != nil {
			t.Fatal(err)
		}
		signed, err := signer.Sign(str(in, "method"), str(in, "request_target"), str(in, "body"), str(in, "timestamp"), str(in, "nonce"))
		if err != nil {
			t.Fatal(err)
		}
		h := asMap(t, v["headers"])
		name := str(v, "name")
		if strOrNil(h, "key_id") != signed[KeyIDHeader] {
			t.Errorf("%s: key id mismatch", name)
		}
		if strOrNil(h, "signature") != signed[SignatureHeader] {
			t.Errorf("%s: signature mismatch", name)
		}
		if strOrNil(h, "payload_hash") != signed[PayloadHashHeader] {
			t.Errorf("%s: payload hash mismatch", name)
		}
		checked++
	}
	if checked < 4 {
		t.Fatalf("expected at least 4 signed_path_vectors checked, got %d", checked)
	}
}

// TestAReferenceServerBuiltOnTheVerifierAgreesWithEverySignedPathVector
// builds a minimal reference server (key lookup by key ID, then Verify) on
// top of this package's public API and checks it reaches the same
// status/reason as every signed_path_vectors entry — proof the verifier
// alone is enough to implement the platform's signed path.
func TestAReferenceServerBuiltOnTheVerifierAgreesWithEverySignedPathVector(t *testing.T) {
	vectors := loadVectors(t, "ingest-signature-vectors.json")
	list := section(t, vectors, "signed_path_vectors")
	if len(list) != 18 {
		t.Fatalf("expected exactly 18 signed_path_vectors, got %d", len(list))
	}
	for _, raw := range list {
		v := asMap(t, raw)
		h := asMap(t, v["headers"])
		knownKeysRaw, _ := v["known_keys"].([]any)

		status, reason := 200, ""
		keyID := strOrNil(h, "key_id")
		apiKeyHeader := v["api_key_header"]
		if keyID != "" && apiKeyHeader != nil {
			status, reason = 400, "ambiguous_credentials"
		} else {
			var key string
			for _, kv := range knownKeysRaw {
				candidate, _ := kv.(string)
				if DeriveKeyID(candidate) == keyID {
					key = candidate
				}
			}
			var result VerifyResult
			if key == "" {
				if wireHeaders(t, v)[SignatureHeader] == "" {
					result = ResultMissing
				} else {
					result = ResultInvalid
				}
			} else {
				result = Verify(key, str(v, "method"), str(v, "request_target"), str(v, "body"), wireHeaders(t, v), num(v, "now_ms"))
			}
			switch result {
			case ResultValid:
				status, reason = 200, ""
			case ResultExpired:
				status, reason = 400, "timestamp_expired"
			case ResultMissing:
				status, reason = 401, "signature_missing"
			case ResultUnsupportedVersion:
				status, reason = 401, "signature_version_unsupported"
			default:
				status, reason = 401, "signature_invalid"
			}
		}

		expected := asMap(t, v["expected"])
		name := str(v, "name")
		if int64(status) != num(expected, "status") {
			t.Errorf("%s: status = %d, want %d", name, status, num(expected, "status"))
		}
		wantReason := ""
		if expected["reason"] != nil {
			wantReason, _ = expected["reason"].(string)
		}
		if reason != wantReason {
			t.Errorf("%s: reason = %q, want %q", name, reason, wantReason)
		}
	}
}

func TestRequestTargetIsThePathAndQueryAsWritten(t *testing.T) {
	cases := map[string]string{
		"https://www.devfortress.net/api/events/ingest": "/api/events/ingest",
		"http://h:3001/gateway/api/x?v=1&x=a%20b#frag":  "/gateway/api/x?v=1&x=a%20b",
		"http://h":        "/",
		"http://h?a=1":    "/?a=1",
		"http://h/x?":     "/x?",
		"http://h/a/../b": "/a/../b",
	}
	for input, want := range cases {
		if got := RequestTargetFromURL(input); got != want {
			t.Errorf("RequestTargetFromURL(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNonceIsADashedV4UUID(t *testing.T) {
	pattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		n, err := UUIDv4()
		if err != nil {
			t.Fatal(err)
		}
		if !pattern.MatchString(n) {
			t.Errorf("UUIDv4() = %q does not match v4 pattern", n)
		}
		seen[n] = true
	}
	if len(seen) != 50 {
		t.Fatalf("expected 50 distinct UUIDs, got %d", len(seen))
	}
}
