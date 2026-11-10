package devfortress

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// SignatureVersion is the request signature contract version this package
// implements. It is sent as the X-DevFortress-Signature-Version header on
// every signed request.
const SignatureVersion = "2"

// ToleranceSeconds is the maximum age, in either direction, a signed
// request's timestamp may have before Verify reports it "expired".
const ToleranceSeconds = 300

// The six request-signature headers (contract v2). All six are required
// together on the signed path, on every method including GET.
const (
	KeyIDHeader       = "X-DevFortress-Key-Id"
	VersionHeader     = "X-DevFortress-Signature-Version"
	NonceHeader       = "X-DevFortress-Nonce"
	TimestampHeader   = "X-DevFortress-Timestamp"
	PayloadHashHeader = "X-DevFortress-Payload-Hash"
	SignatureHeader   = "X-DevFortress-Signature"
)

// VerifyResult is the outcome of Verify: "valid", "invalid" (headers
// present, mismatch), "expired" (correct signature, timestamp outside
// tolerance), "missing" (a required header is absent) or
// "unsupported_version" (version header absent or not "2").
type VerifyResult string

const (
	ResultValid              VerifyResult = "valid"
	ResultInvalid            VerifyResult = "invalid"
	ResultExpired            VerifyResult = "expired"
	ResultMissing            VerifyResult = "missing"
	ResultUnsupportedVersion VerifyResult = "unsupported_version"
)

// SignedHeaders holds the six signing headers produced by Sign, keyed by
// their wire header name.
type SignedHeaders map[string]string

// Signer computes request integrity headers for every SDK-to-platform call
// (contract v2).
//
// Canonical string: "{METHOD}.{requestTarget}.{timestamp}.{nonce}.{payloadHash}"
// where METHOD is the uppercase HTTP method, requestTarget is the URL path
// plus "?query" exactly as sent (no host, no re-encoding), and payloadHash is
// the lowercase hex SHA-256 of the exact body bytes (the empty string for a
// request with no body). The signature is the lowercase hex HMAC-SHA256 of
// that string, keyed with the project API key (UTF-8). The timestamp is Unix
// epoch milliseconds; the nonce is a dashed UUID v4, fresh for every request
// attempt. Tolerance is 300 seconds.
//
// The API key never travels on a signed request. X-DevFortress-Key-Id is a
// non-secret identifier derived from the key (first 32 hex characters of its
// SHA-256); the platform verifies the HMAC with the key it has stored.
type Signer struct {
	apiKey string
}

// NewSigner returns a Signer for apiKey. An empty key is rejected.
func NewSigner(apiKey string) (*Signer, error) {
	if apiKey == "" {
		return nil, errors.New("devfortress: an API key is required")
	}
	return &Signer{apiKey: apiKey}, nil
}

// DeriveKeyID returns the non-secret key ID for apiKey: the first 32
// lowercase hex characters of SHA-256 over the UTF-8 key.
func DeriveKeyID(apiKey string) string {
	sum := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(sum[:])[:32]
}

// KeyID returns this signer's non-secret key ID.
func (s *Signer) KeyID() string {
	return DeriveKeyID(s.apiKey)
}

// Sign returns the six signing headers for one request attempt. An empty
// timestamp or nonce is filled in fresh (current time, random UUID v4); pass
// both explicitly only to reproduce a fixed vector in tests.
func (s *Signer) Sign(method, requestTarget, body, timestamp, nonce string) (SignedHeaders, error) {
	ts := timestamp
	if ts == "" {
		ts = nowMsString()
	}
	n := nonce
	if n == "" {
		var err error
		n, err = UUIDv4()
		if err != nil {
			return nil, fmt.Errorf("devfortress: could not generate a nonce: %w", err)
		}
	}
	payloadHash, signature := digest(s.apiKey, method, requestTarget, ts, n, body)

	return SignedHeaders{
		KeyIDHeader:       s.KeyID(),
		VersionHeader:     SignatureVersion,
		NonceHeader:       n,
		TimestampHeader:   ts,
		PayloadHashHeader: payloadHash,
		SignatureHeader:   signature,
	}, nil
}

// Verify mirrors the platform's check for a signed request and returns
// "valid", "invalid", "expired", "missing" or "unsupported_version". headers
// uses the wire header names (KeyIDHeader, VersionHeader, ...). nowMs is the
// current time as Unix epoch milliseconds, supplied by the caller so the
// result is reproducible in tests.
func Verify(apiKey, method, requestTarget, body string, headers map[string]string, nowMs int64) VerifyResult {
	nonce := headers[NonceHeader]
	ts := headers[TimestampHeader]
	payloadHash := headers[PayloadHashHeader]
	signature := headers[SignatureHeader]
	if nonce == "" || ts == "" || payloadHash == "" || signature == "" {
		return ResultMissing
	}
	if headers[VersionHeader] != SignatureVersion {
		return ResultUnsupportedVersion
	}

	expectedHash, expectedSig := digest(apiKey, method, requestTarget, ts, nonce, body)
	hashOK := hmac.Equal([]byte(strings.ToLower(expectedHash)), []byte(strings.ToLower(payloadHash)))
	sigOK := hmac.Equal([]byte(strings.ToLower(expectedSig)), []byte(strings.ToLower(signature)))
	if !(hashOK && sigOK) {
		return ResultInvalid
	}

	if !tsPattern.MatchString(ts) {
		return ResultInvalid
	}
	tsInt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return ResultInvalid
	}
	age := nowMs - tsInt
	if age < 0 {
		age = -age
	}
	if age > ToleranceSeconds*1000 {
		return ResultExpired
	}
	return ResultValid
}

var tsPattern = regexp.MustCompile(`^-?[0-9]+$`)

var schemeAuthorityPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.\-]*://[^/?]*`)

// RequestTargetFromURL returns the request target for rawURL: the path plus
// "?query" as written, with no scheme, host or fragment, and nothing
// re-encoded or normalised. An empty path is "/".
func RequestTargetFromURL(rawURL string) string {
	url := rawURL
	if idx := strings.IndexByte(url, '#'); idx != -1 {
		url = url[:idx]
	}
	rest := schemeAuthorityPattern.ReplaceAllString(url, "")
	if rest == "" || rest[0] == '?' {
		return "/" + rest
	}
	return rest
}

// UUIDv4 returns a dashed UUID v4 from crypto/rand.
func UUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// nowMsString returns the current Unix epoch milliseconds as a decimal string.
func nowMsString() string {
	return strconv.FormatInt(time.Now().UnixMilli(), 10)
}

func digest(apiKey, method, requestTarget, timestamp, nonce, body string) (payloadHash, signature string) {
	sum := sha256.Sum256([]byte(body))
	payloadHash = hex.EncodeToString(sum[:])
	canonical := strings.ToUpper(method) + "." + requestTarget + "." + timestamp + "." + nonce + "." + payloadHash

	mac := hmac.New(sha256.New, []byte(apiKey))
	mac.Write([]byte(canonical))
	signature = hex.EncodeToString(mac.Sum(nil))
	return payloadHash, signature
}
