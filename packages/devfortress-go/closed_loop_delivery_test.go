package devfortress

// Closed-loop local self-enforcement — TODO 358 regression coverage.
//
// Node's own external-mode reference (devfortress.ts's handleWebhook/
// isBlocked pair) and Python's ClosedLoopEngine both self-enforce
// block/revocation decisions via a local cache, checked unconditionally
// before any remote fallback. This SDK previously only delivered and
// verified these commands, leaving every embedding app to implement its
// own cache. These tests cover the ported local-cache behavior.

import "testing"

func TestResponseWebhookClient_IPBlockCachedWhenSeverityHighOrCritical(t *testing.T) {
	c := NewResponseWebhookClient("https://example.test/webhook", "secret", nil)

	if c.IsIPBlocked("1.2.3.4") {
		t.Fatal("expected IP not blocked before any inbound command recorded")
	}

	c.RecordInboundCommand(WebhookCommand{Type: "ip_block", IP: "1.2.3.4", Severity: "high"})

	if !c.IsIPBlocked("1.2.3.4") {
		t.Fatal("expected IP blocked after a high-severity ip_block command")
	}
}

func TestResponseWebhookClient_IPBlockNotCachedWhenSeverityLow(t *testing.T) {
	c := NewResponseWebhookClient("https://example.test/webhook", "secret", nil)

	c.RecordInboundCommand(WebhookCommand{Type: "ip_block", IP: "5.6.7.8", Severity: "low"})

	if c.IsIPBlocked("5.6.7.8") {
		t.Fatal("expected low-severity ip_block command not to be cached as blocked")
	}
}

func TestResponseWebhookClient_IPBlockDefaultsToCachedWhenSeverityUnset(t *testing.T) {
	c := NewResponseWebhookClient("https://example.test/webhook", "secret", nil)

	c.RecordInboundCommand(WebhookCommand{Type: "ip_block", IP: "9.9.9.9"})

	if !c.IsIPBlocked("9.9.9.9") {
		t.Fatal("expected ip_block with unset severity to be cached (matches DeliverIPBlock's own high-severity default)")
	}
}

func TestResponseWebhookClient_SessionRevocationCachesUser(t *testing.T) {
	c := NewResponseWebhookClient("https://example.test/webhook", "secret", nil)

	if c.IsUserBlocked("user-1") {
		t.Fatal("expected user not blocked before any inbound command recorded")
	}

	c.RecordInboundCommand(WebhookCommand{Type: "session_revocation", UserID: "user-1", IP: "10.0.0.1"})

	if !c.IsUserBlocked("user-1") {
		t.Fatal("expected user blocked after session_revocation command")
	}
	if !c.IsIPBlocked("10.0.0.1") {
		t.Fatal("expected IP blocked after session_revocation command carrying an IP")
	}
}

func TestResponseWebhookClient_UnrelatedIPOrUserNotBlocked(t *testing.T) {
	c := NewResponseWebhookClient("https://example.test/webhook", "secret", nil)
	c.RecordInboundCommand(WebhookCommand{Type: "ip_block", IP: "1.1.1.1", Severity: "critical"})

	if c.IsIPBlocked("2.2.2.2") {
		t.Fatal("unrelated IP must not be reported as blocked")
	}
	if c.IsUserBlocked("unrelated-user") {
		t.Fatal("unrelated user must not be reported as blocked")
	}
}
