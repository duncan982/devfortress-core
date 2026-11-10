package devfortress

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func TestEveryWebhookVectorGivesItsExpectedVerdict(t *testing.T) {
	vectors := loadVectors(t, "webhook-signature-vectors.json")
	list := section(t, vectors, "vectors")
	if len(list) < 15 {
		t.Fatalf("expected at least 15 webhook vectors, got %d", len(list))
	}
	for _, raw := range list {
		v := asMap(t, raw)
		now := mustParseWebhookNow(t, str(v, "now"))
		result := VerifyWebhook(str(v, "body"), str(v, "signature"), str(v, "timestamp"), str(v, "secret"), WithWebhookNow(now))
		wantValid, _ := v["expected_valid"].(bool)
		if result.Valid != wantValid {
			t.Errorf("%s: valid = %v, want %v (reason %q)", str(v, "name"), result.Valid, wantValid, result.Reason)
		}
	}
}

func mustParseWebhookNow(t *testing.T, iso string) time.Time {
	t.Helper()
	ms, ok := parseISOMs(iso)
	if !ok {
		t.Fatalf("could not parse now %q", iso)
	}
	return time.UnixMilli(ms).UTC()
}

func signWebhook(ts, body, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "." + body))
	return hex.EncodeToString(mac.Sum(nil))
}

func TestValidTamperedStaleAndWrongSecretCases(t *testing.T) {
	secret := "whsec_unit_test_secret"
	body := `{"event_id":"e1"}`
	ts := "2026-01-15T12:00:00.000Z"
	sig := signWebhook(ts, body, secret)
	now := mustParseWebhookNow(t, ts)

	if !VerifyWebhook(body, sig, ts, secret, WithWebhookNow(now)).Valid {
		t.Error("expected valid signature to verify")
	}
	if got := VerifyWebhook(body+" ", sig, ts, secret, WithWebhookNow(now)).Reason; got != "signature_mismatch" {
		t.Errorf("tampered body: got %q", got)
	}
	if got := VerifyWebhook(body, signWebhook(ts, body, "other"), ts, secret, WithWebhookNow(now)).Reason; got != "signature_mismatch" {
		t.Errorf("wrong secret: got %q", got)
	}
	if got := VerifyWebhook(body, sig, ts, secret, WithWebhookNow(mustParseWebhookNow(t, "2026-01-15T12:05:01.000Z"))).Reason; got != "timestamp_expired" {
		t.Errorf("just past tolerance: got %q", got)
	}
	if !VerifyWebhook(body, sig, ts, secret, WithWebhookNow(mustParseWebhookNow(t, "2026-01-15T12:05:00.000Z"))).Valid {
		t.Error("expected exactly-at-tolerance to be valid")
	}
	if got := VerifyWebhook(body, sig, "yesterday", secret, WithWebhookNow(now)).Reason; got != "invalid_timestamp" {
		t.Errorf("unparseable timestamp: got %q", got)
	}
	if got := VerifyWebhook(body, "abc", ts, secret, WithWebhookNow(now)).Reason; got != "invalid_signature" {
		t.Errorf("short signature: got %q", got)
	}
	if got := VerifyWebhook(body, sig+"\n", ts, secret, WithWebhookNow(now)).Reason; got != "invalid_signature" {
		t.Errorf("trailing newline signature: got %q", got)
	}
}

func TestAnOffsetTimestampIsConvertedToUTC(t *testing.T) {
	secret := "s"
	body := "{}"
	ts := "2026-01-15T14:00:00.000+02:00"
	sig := signWebhook(ts, body, secret)

	if !VerifyWebhook(body, sig, ts, secret, WithWebhookNow(mustParseWebhookNow(t, "2026-01-15T12:00:10.000Z"))).Valid {
		t.Error("expected offset timestamp within tolerance to be valid")
	}
	if got := VerifyWebhook(body, sig, ts, secret, WithWebhookNow(mustParseWebhookNow(t, "2026-01-15T12:06:00.000Z"))).Reason; got != "timestamp_expired" {
		t.Errorf("got %q", got)
	}
}

func TestNonceReplayIsDetectedThroughTheCallback(t *testing.T) {
	body := `{"nonce":"a1b2c3d4e5f60718293a4b5c6d7e8f90"}`
	ts := "2026-01-15T12:00:00.000Z"
	sig := signWebhook(ts, body, "s")
	seen := map[string]bool{}
	check := func(nonce string) bool {
		if seen[nonce] {
			return false
		}
		seen[nonce] = true
		return true
	}

	first := VerifyWebhook(body, sig, ts, "s", WithWebhookNow(mustParseWebhookNow(t, ts)), WithNonceCheck(check))
	if !first.Valid {
		t.Fatalf("expected first delivery valid, got reason %q", first.Reason)
	}
	second := VerifyWebhook(body, sig, ts, "s", WithWebhookNow(mustParseWebhookNow(t, ts)), WithNonceCheck(check))
	if second.Valid || second.Reason != "replay_detected" {
		t.Errorf("expected replay_detected, got valid=%v reason=%q", second.Valid, second.Reason)
	}
}

func TestAMissingOrMalformedNonceFailsWhenReplayTrackingIsOn(t *testing.T) {
	ts := "2026-01-15T12:00:00.000Z"
	always := func(string) bool { return true }
	cases := map[string]string{
		"{}":                "nonce_invalid",
		`{"nonce":"short"}`: "nonce_invalid",
		"[1]":               "invalid_body",
		"not json":          "invalid_body",
	}
	for body, wantReason := range cases {
		result := VerifyWebhook(body, signWebhook(ts, body, "s"), ts, "s", WithWebhookNow(mustParseWebhookNow(t, ts)), WithNonceCheck(always))
		if result.Reason != wantReason {
			t.Errorf("body %q: got reason %q, want %q", body, result.Reason, wantReason)
		}
	}
}
