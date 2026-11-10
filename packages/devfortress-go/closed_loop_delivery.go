package devfortress

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"
)

// webhookRateWindow and webhookRateLimit match the Node SDK's S28 webhook
// flooding protection: at most this many deliveries per endpoint per window.
const (
	webhookRateWindow = time.Minute
	webhookRateLimit  = 60
)

// DeliveryOutcome is the result of one outbound webhook command delivery.
type DeliveryOutcome struct {
	Delivered bool
	AckTime   time.Duration
}

// SessionRevocationParams is the payload for DeliverSessionRevocation.
type SessionRevocationParams struct {
	SessionID string
	UserID    string
	Reason    string
	IP        string
}

// IPBlockParams is the payload for DeliverIPBlock.
type IPBlockParams struct {
	IP       string
	Reason   string
	TTL      time.Duration
	Severity ThreatSeverity
}

// ThreatSeverity mirrors the platform's severity levels for outbound
// commands.
type ThreatSeverity string

const (
	SeverityThreatLow      ThreatSeverity = "low"
	SeverityThreatMedium   ThreatSeverity = "medium"
	SeverityThreatHigh     ThreatSeverity = "high"
	SeverityThreatCritical ThreatSeverity = "critical"
)

type webhookRateBucket struct {
	count       int
	windowStart time.Time
}

// blockCacheMaxEntries and defaultBlockCacheTTL size the local
// self-enforcement cache below (TODO 358).
const (
	blockCacheMaxEntries = 10_000
	defaultBlockCacheTTL = time.Hour
)

// ResponseWebhookClient delivers closed-loop response commands (session
// revocation, IP block) to a single customer-configured webhook endpoint
// — the outbound direction of the closed loop, complementing VerifyWebhook
// (the inbound direction: verifying a command the platform sent to this
// application). Every delivery is HMAC-SHA256 signed the same way
// VerifyWebhook checks it (hex HMAC over "{timestamp}.{body}"), rate
// limited per endpoint (60/min), and awaited with a short SLA timeout.
// Safe for concurrent use.
type ResponseWebhookClient struct {
	url       string
	secret    string
	transport Transport

	mu      sync.Mutex
	buckets map[string]*webhookRateBucket
	cache   *lruCache
}

// NewResponseWebhookClient returns a client that delivers signed commands
// to url, signed with secret. transport may be nil (the default
// HTTPTransport is used).
func NewResponseWebhookClient(url, secret string, transport Transport) *ResponseWebhookClient {
	if transport == nil {
		transport = NewHTTPTransport()
	}
	return &ResponseWebhookClient{url: url, secret: secret, transport: transport, buckets: make(map[string]*webhookRateBucket)}
}

// DeliverSessionRevocation delivers a session-revocation command, awaiting
// acknowledgement with a 2-second SLA timeout.
func (c *ResponseWebhookClient) DeliverSessionRevocation(ctx context.Context, params SessionRevocationParams) DeliveryOutcome {
	if c.url == "" || c.secret == "" {
		return DeliveryOutcome{}
	}
	if !c.checkRateLimit(c.url) {
		return DeliveryOutcome{}
	}

	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	body, _ := json.Marshal(map[string]any{
		"type": "session_revocation", "session_id": params.SessionID,
		"user_id": nilIfEmpty(params.UserID), "reason": params.Reason,
		"ip": nilIfEmpty(params.IP), "issued_at": timestamp,
	})

	return c.deliver(ctx, timestamp, body, 2*time.Second)
}

// DeliverIPBlock delivers an IP-block command so the customer can enforce
// at the edge (CDN/WAF/load balancer), awaiting acknowledgement with a
// 5-second SLA timeout.
func (c *ResponseWebhookClient) DeliverIPBlock(ctx context.Context, params IPBlockParams) DeliveryOutcome {
	if c.url == "" || c.secret == "" {
		return DeliveryOutcome{}
	}
	if !c.checkRateLimit(c.url) {
		return DeliveryOutcome{}
	}

	ttl := params.TTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	severity := params.Severity
	if severity == "" {
		severity = SeverityThreatHigh
	}
	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	body, _ := json.Marshal(map[string]any{
		"type": "ip_block", "ip": params.IP, "reason": params.Reason,
		"ttl_seconds": int(ttl.Seconds()), "severity": severity, "issued_at": timestamp,
	})

	return c.deliver(ctx, timestamp, body, 5*time.Second)
}

func (c *ResponseWebhookClient) deliver(ctx context.Context, timestamp string, body []byte, timeout time.Duration) DeliveryOutcome {
	signature := signWebhookBody(timestamp, body, c.secret)
	start := time.Now()
	_, err := c.transport.Send(ctx, "POST", c.url, map[string]string{
		"Content-Type":            "application/json",
		WebhookSignatureHeader:    signature,
		WebhookTimestampHeader:    timestamp,
	}, body, timeout)
	ack := time.Since(start)
	return DeliveryOutcome{Delivered: err == nil, AckTime: ack}
}

// checkRateLimit reports whether a delivery to endpointURL is allowed
// right now (S28 webhook flooding protection).
func (c *ResponseWebhookClient) checkRateLimit(endpointURL string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	bucket := c.buckets[endpointURL]
	if bucket == nil || now.Sub(bucket.windowStart) >= webhookRateWindow {
		c.buckets[endpointURL] = &webhookRateBucket{count: 1, windowStart: now}
		return true
	}
	if bucket.count >= webhookRateLimit {
		return false
	}
	bucket.count++
	return true
}

func signWebhookBody(timestamp string, body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp + "."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// WebhookCommand is a parsed, already-verified inbound command from the
// platform (session_revocation or ip_block) — the inbound direction of
// the closed loop. Call VerifyWebhook first; ParseWebhookCommand does not
// re-verify the signature.
type WebhookCommand struct {
	Type      string // "session_revocation" or "ip_block"
	SessionID string
	UserID    string
	IP        string
	Reason    string
	TTLSeconds int
	Severity  string
	IssuedAt  string
}

// ParseWebhookCommand decodes a verified webhook body into a WebhookCommand.
func ParseWebhookCommand(rawBody []byte) (WebhookCommand, error) {
	var decoded struct {
		Type       string `json:"type"`
		SessionID  string `json:"session_id"`
		UserID     string `json:"user_id"`
		IP         string `json:"ip"`
		Reason     string `json:"reason"`
		TTLSeconds int    `json:"ttl_seconds"`
		Severity   string `json:"severity"`
		IssuedAt   string `json:"issued_at"`
	}
	if err := json.Unmarshal(rawBody, &decoded); err != nil {
		return WebhookCommand{}, err
	}
	return WebhookCommand{
		Type: decoded.Type, SessionID: decoded.SessionID, UserID: decoded.UserID,
		IP: decoded.IP, Reason: decoded.Reason, TTLSeconds: decoded.TTLSeconds,
		Severity: decoded.Severity, IssuedAt: decoded.IssuedAt,
	}, nil
}

// IsIPBlocked reports whether ip was locally cached as blocked by a prior
// RecordInboundCommand call — local-only, no network call. Mirrors Node's
// own external-mode isBlocked()/memGet pair and Python's
// ClosedLoopEngine.is_blocked_ip (TODO 358): this SDK previously delivered
// and verified block/revocation commands but never self-enforced them
// locally, leaving every embedding app to implement its own cache.
func (c *ResponseWebhookClient) IsIPBlocked(ip string) bool {
	return c.hasBlock("blocked:ip:" + ip)
}

// IsUserBlocked reports whether userID was locally cached as blocked by a
// prior RecordInboundCommand call — local-only, no network call.
func (c *ResponseWebhookClient) IsUserBlocked(userID string) bool {
	return c.hasBlock("blocked:user:" + userID)
}

// RecordInboundCommand locally caches the block/revocation decision carried
// by an already-verified inbound WebhookCommand (see VerifyWebhook +
// ParseWebhookCommand), so a subsequent IsIPBlocked/IsUserBlocked call
// enforces it without a remote round-trip.
//
// An "ip_block" command is cached only when its severity is "critical" or
// "high" (or unset — every DeliverIPBlock call in this package defaults to
// "high" when the sender leaves it empty), matching Node/Python's own
// severity gate. A "session_revocation" command carries no severity field
// on this SDK's wire shape (see DeliverSessionRevocation's body) — its
// delivery already represents a decided enforcement action, so it is
// always cached.
func (c *ResponseWebhookClient) RecordInboundCommand(cmd WebhookCommand) {
	ttl := time.Duration(cmd.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = defaultBlockCacheTTL
	}

	switch cmd.Type {
	case "ip_block":
		if cmd.Severity != "" && cmd.Severity != string(SeverityThreatHigh) && cmd.Severity != string(SeverityThreatCritical) {
			return
		}
		if cmd.IP != "" {
			c.cacheBlock("blocked:ip:"+cmd.IP, ttl)
		}
	case "session_revocation":
		if cmd.UserID != "" {
			c.cacheBlock("blocked:user:"+cmd.UserID, ttl)
		}
		if cmd.IP != "" {
			c.cacheBlock("blocked:ip:"+cmd.IP, ttl)
		}
	}
}

func (c *ResponseWebhookClient) cacheBlock(key string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache == nil {
		c.cache = newLRUCache(blockCacheMaxEntries, defaultBlockCacheTTL)
	}
	c.cache.set(key, "1", ttl)
}

func (c *ResponseWebhookClient) hasBlock(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache == nil {
		return false
	}
	return c.cache.has(key)
}
