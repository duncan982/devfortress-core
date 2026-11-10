package net.devfortress.springboot;

import jakarta.servlet.FilterChain;
import net.devfortress.Client;
import net.devfortress.PlatformCircuitBreaker;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Internal/hybrid-mode pre-response gate (TODO 407 port) — adapter-level
 * proof that {@link DevFortressFilter} actually wires {@link
 * Client#observe} into the real servlet filter chain, following the same
 * bar as the already-completed Ruby Rails adapter's {@code
 * middleware_test.rb} internal-mode tests (real middleware class, real
 * mock request, real 403 short-circuit — not just engine-level unit
 * tests).
 */
class DevFortressFilterInternalGateTest {

    private static Client internalClient() {
        return Client.builder("test-key").transport(new RecordingTransport()).mode("internal").build();
    }

    private static Client hybridClient() {
        return Client.builder("test-key").transport(new RecordingTransport()).mode("hybrid").build();
    }

    @Test
    void internalModeCleanRequestReachesTheApp() throws Exception {
        try (Client client = internalClient()) {
            DevFortressFilter filter = new DevFortressFilter(client);
            AtomicBoolean appCalled = new AtomicBoolean();
            FilterChain chain = (req, res) -> {
                appCalled.set(true);
                ((MockHttpServletResponse) res).setStatus(200);
            };

            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/products");
            request.setQueryString("q=laptop");
            request.setRemoteAddr("203.0.113.11");
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilter(request, response, chain);

            assertTrue(appCalled.get());
            assertEquals(200, response.getStatus());
        }
    }

    @Test
    void internalModeSensitiveFileAccessIsBlockedBeforeReachingTheApp() throws Exception {
        try (Client client = internalClient()) {
            DevFortressFilter filter = new DevFortressFilter(client);
            AtomicBoolean appCalled = new AtomicBoolean();
            FilterChain chain = (req, res) -> {
                appCalled.set(true);
                ((MockHttpServletResponse) res).setStatus(200);
            };

            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/.env");
            request.setRemoteAddr("198.51.100.20");
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilter(request, response, chain);

            assertFalse(appCalled.get(), "the app must never see a blocked request");
            assertEquals(403, response.getStatus());
            assertEquals("application/json", response.getContentType());
            String body = response.getContentAsString();
            assertTrue(body.contains("\"error\":\"blocked\""), "unexpected body: " + body);
            assertTrue(client.isBlocked("198.51.100.20"));
        }
    }

    @Test
    void internalModeBlockedIpStaysBlockedOnALaterCleanRequest() throws Exception {
        try (Client client = internalClient()) {
            DevFortressFilter filter = new DevFortressFilter(client);
            FilterChain chain = (req, res) -> ((MockHttpServletResponse) res).setStatus(200);

            MockHttpServletRequest attack = new MockHttpServletRequest("GET", "/.env");
            attack.setRemoteAddr("198.51.100.21");
            MockHttpServletResponse firstResponse = new MockHttpServletResponse();
            filter.doFilter(attack, firstResponse, chain);
            assertEquals(403, firstResponse.getStatus());

            MockHttpServletRequest clean = new MockHttpServletRequest("GET", "/products");
            clean.setRemoteAddr("198.51.100.21");
            MockHttpServletResponse secondResponse = new MockHttpServletResponse();
            filter.doFilter(clean, secondResponse, chain);

            assertEquals(403, secondResponse.getStatus(), "the IP must still be blocked by the engine's own state");
        }
    }

    @Test
    void externalModeIsUnaffectedByTheInternalGate() throws Exception {
        try (Client client = Client.builder("test-key").transport(new RecordingTransport()).build()) {
            DevFortressFilter filter = new DevFortressFilter(client);
            AtomicBoolean appCalled = new AtomicBoolean();
            FilterChain chain = (req, res) -> {
                appCalled.set(true);
                ((MockHttpServletResponse) res).setStatus(200);
            };

            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/.env");
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilter(request, response, chain);

            // External mode has no internal engine, so even a sensitive-file path
            // reaches the app unblocked — the gate is a no-op outside internal/
            // hybrid mode.
            assertTrue(appCalled.get());
            assertEquals(200, response.getStatus());
        }
    }

    @Test
    void hybridModeBlocksViaInternalFirstSameAsInternalMode() throws Exception {
        try (Client client = hybridClient()) {
            DevFortressFilter filter = new DevFortressFilter(client);
            AtomicBoolean appCalled = new AtomicBoolean();
            FilterChain chain = (req, res) -> {
                appCalled.set(true);
                ((MockHttpServletResponse) res).setStatus(200);
            };

            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/.env");
            request.setRemoteAddr("198.51.100.22");
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilter(request, response, chain);

            assertFalse(appCalled.get());
            assertEquals(403, response.getStatus());
            assertEquals(PlatformCircuitBreaker.State.CLOSED, client.getCircuitBreaker().getState(),
                    "the circuit breaker must stay closed — no second relay/external call for a decision the internal engine already flagged");
        }
    }

    @Test
    void excludedHealthPathBypassesTheInternalGateEvenInInternalMode() throws Exception {
        try (Client client = internalClient()) {
            DevFortressFilter filter = new DevFortressFilter(client);
            AtomicBoolean appCalled = new AtomicBoolean();
            FilterChain chain = (req, res) -> {
                appCalled.set(true);
                ((MockHttpServletResponse) res).setStatus(200);
            };

            // /health is in DEFAULT_EXCLUDE_PATHS; even though its query string
            // below would otherwise match sql_injection, the gate must not run at all.
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/health");
            request.setQueryString("q=' OR 1=1 --");
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilter(request, response, chain);

            assertTrue(appCalled.get());
            assertEquals(200, response.getStatus());
        }
    }
}
