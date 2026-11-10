package net.devfortress;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Closed-loop local self-enforcement — TODO 358 regression coverage.
 *
 * <p>Node's own external-mode reference (devfortress.ts's handleWebhook/isBlocked pair) and
 * Python's ClosedLoopEngine both self-enforce block/revocation decisions via a local cache,
 * checked unconditionally before any remote fallback. This SDK previously only delivered and
 * verified these commands, leaving every embedding app to implement its own cache. These tests
 * cover the ported local-cache behavior.
 */
class ResponseWebhookClientClosedLoopTest {
    private static Map<String, Object> command(Object... kv) {
        Map<String, Object> map = new HashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            map.put((String) kv[i], kv[i + 1]);
        }
        return map;
    }

    @Test
    void ipBlockCachedWhenSeverityHighOrCritical() {
        ResponseWebhookClient client = new ResponseWebhookClient("https://example.test/webhook", "secret");
        assertFalse(client.isIpBlocked("1.2.3.4"));

        client.recordInboundCommand(command("type", "ip_block", "ip", "1.2.3.4", "severity", "high"));

        assertTrue(client.isIpBlocked("1.2.3.4"));
    }

    @Test
    void ipBlockNotCachedWhenSeverityLow() {
        ResponseWebhookClient client = new ResponseWebhookClient("https://example.test/webhook", "secret");

        client.recordInboundCommand(command("type", "ip_block", "ip", "5.6.7.8", "severity", "low"));

        assertFalse(client.isIpBlocked("5.6.7.8"));
    }

    @Test
    void ipBlockDefaultsToCachedWhenSeverityUnset() {
        ResponseWebhookClient client = new ResponseWebhookClient("https://example.test/webhook", "secret");

        client.recordInboundCommand(command("type", "ip_block", "ip", "9.9.9.9"));

        assertTrue(client.isIpBlocked("9.9.9.9"));
    }

    @Test
    void sessionRevocationCachesUserAndIp() {
        ResponseWebhookClient client = new ResponseWebhookClient("https://example.test/webhook", "secret");
        assertFalse(client.isUserBlocked("user-1"));

        client.recordInboundCommand(command("type", "session_revocation", "user_id", "user-1", "ip", "10.0.0.1"));

        assertTrue(client.isUserBlocked("user-1"));
        assertTrue(client.isIpBlocked("10.0.0.1"));
    }

    @Test
    void unrelatedIpOrUserNotBlocked() {
        ResponseWebhookClient client = new ResponseWebhookClient("https://example.test/webhook", "secret");
        client.recordInboundCommand(command("type", "ip_block", "ip", "1.1.1.1", "severity", "critical"));

        assertFalse(client.isIpBlocked("2.2.2.2"));
        assertFalse(client.isUserBlocked("unrelated-user"));
    }
}
