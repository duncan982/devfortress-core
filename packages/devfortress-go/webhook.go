package devfortress

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strconv"
	"time"
)

// Webhook verification constants, matching the platform dispatcher
// (POST /api/webhooks/deliver).
const (
	WebhookToleranceSeconds = 300
	WebhookSignatureHeader  = "X-DevFortress-Signature"
	WebhookTimestampHeader  = "X-DevFortress-Timestamp"
)

// WebhookVerification is the outcome of VerifyWebhook.
type WebhookVerification struct {
	Valid bool
	// Reason is empty when Valid is true, otherwise one of:
	// "invalid_timestamp", "timestamp_expired", "invalid_signature",
	// "signature_mismatch", "invalid_body", "nonce_invalid",
	// "replay_detected".
	Reason string
}

type webhookOptions struct {
	tolerance  time.Duration
	now        *time.Time
	nonceCheck func(string) bool
}

// WebhookOption configures VerifyWebhook.
type WebhookOption func(*webhookOptions)

// WithWebhookTolerance overrides the default 300-second timestamp
// tolerance.
func WithWebhookTolerance(d time.Duration) WebhookOption {
	return func(o *webhookOptions) { o.tolerance = d }
}

// WithWebhookNow overrides "now" for tests; production callers omit it.
func WithWebhookNow(t time.Time) WebhookOption {
	return func(o *webhookOptions) { o.now = &t }
}

// WithNonceCheck supplies a callback that returns true the first time a
// nonce is seen and false on replay. When supplied, a missing or malformed
// nonce fails verification. The library keeps no state; replay tracking is
// the caller's.
func WithNonceCheck(check func(nonce string) bool) WebhookOption {
	return func(o *webhookOptions) { o.nonceCheck = check }
}

// VerifyWebhook verifies a DevFortress webhook. rawBody must be exactly the
// bytes received.
//
// X-DevFortress-Timestamp is the ISO-8601 UTC timestamp of dispatch;
// X-DevFortress-Signature is the hex HMAC-SHA256, keyed with the project's
// webhook secret, over the UTF-8 bytes of "{timestamp}.{rawBody}".
func VerifyWebhook(rawBody, signature, timestamp, secret string, opts ...WebhookOption) WebhookVerification {
	o := webhookOptions{tolerance: WebhookToleranceSeconds * time.Second}
	for _, opt := range opts {
		opt(&o)
	}

	tsMs, ok := parseISOMs(timestamp)
	if !ok {
		return WebhookVerification{Reason: "invalid_timestamp"}
	}
	now := time.Now()
	if o.now != nil {
		now = *o.now
	}
	ageMs := now.UnixMilli() - tsMs
	if ageMs > o.tolerance.Milliseconds() {
		return WebhookVerification{Reason: "timestamp_expired"}
	}

	if !hexSigPattern.MatchString(signature) {
		return WebhookVerification{Reason: "invalid_signature"}
	}
	given, err := hex.DecodeString(signature)
	if err != nil {
		return WebhookVerification{Reason: "invalid_signature"}
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp + "." + rawBody))
	expected := mac.Sum(nil)
	if !hmac.Equal(expected, given) {
		return WebhookVerification{Reason: "signature_mismatch"}
	}

	if o.nonceCheck != nil {
		var decoded map[string]any
		if err := json.Unmarshal([]byte(rawBody), &decoded); err != nil {
			return WebhookVerification{Reason: "invalid_body"}
		}
		nonce, _ := decoded["nonce"].(string)
		if !hexNoncePattern.MatchString(nonce) {
			return WebhookVerification{Reason: "nonce_invalid"}
		}
		if !o.nonceCheck(nonce) {
			return WebhookVerification{Reason: "replay_detected"}
		}
	}

	return WebhookVerification{Valid: true}
}

var (
	hexSigPattern   = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	hexNoncePattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
	isoPattern      = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$`)
)

// parseISOMs returns epoch milliseconds for an ISO-8601 timestamp with a
// zone, or false when value is malformed or not a valid calendar date.
func parseISOMs(value string) (int64, bool) {
	m := isoPattern.FindStringSubmatch(value)
	if m == nil {
		return 0, false
	}
	year, _ := strconv.Atoi(m[1])
	month, _ := strconv.Atoi(m[2])
	day, _ := strconv.Atoi(m[3])
	hour, _ := strconv.Atoi(m[4])
	minute, _ := strconv.Atoi(m[5])
	second, _ := strconv.Atoi(m[6])
	frac := m[7]
	zone := m[8]

	if hour > 23 || minute > 59 || second > 59 {
		return 0, false
	}

	t := time.Date(year, time.Month(month), day, hour, minute, second, 0, time.UTC)
	if t.Year() != year || int(t.Month()) != month || t.Day() != day {
		return 0, false // not a real calendar date (mirrors PHP's checkdate)
	}

	ms := t.UnixMilli()
	fracDigits := frac
	if len(fracDigits) > 3 {
		fracDigits = fracDigits[:3]
	}
	for len(fracDigits) < 3 {
		fracDigits += "0"
	}
	millis, _ := strconv.Atoi(fracDigits)
	ms += int64(millis)

	if zone != "Z" {
		sign := int64(1)
		if zone[0] == '-' {
			sign = -1
		}
		offsetH, _ := strconv.Atoi(zone[1:3])
		offsetM, _ := strconv.Atoi(zone[4:6])
		offset := int64(offsetH)*3600 + int64(offsetM)*60
		ms -= sign * offset * 1000
	}

	return ms, true
}
