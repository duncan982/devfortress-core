package net.devfortress.springboot;

import jakarta.servlet.FilterChain;
import net.devfortress.Client;
import net.devfortress.Transport;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * THE regression test this whole adapter exists for: a single sparse
 * request through the real {@link DevFortressFilter} — far below the
 * client's batch size (25), with no flush interval configured — must still
 * be delivered, and must not add latency to the response. This is the Go
 * SDK gin adapter's original sparse-traffic gap (discovered live, fixed
 * after the fact — see the SDK audit notes); the Spring Boot adapter is
 * built against {@code Observer.observeAndFlush} from the start specifically
 * so it never has this gap. If this test ever fails, do not "fix" it by
 * lowering the batch size or adding a flush interval to the demo — that
 * would hide the adapter's own bug instead of fixing it.
 */
class SparseDeliveryRegressionTest {
    @Test
    void aSingleRequestIsDeliveredWithoutWaitingForBatchSizeOrInterval() throws Exception {
        RecordingTransport transport = new RecordingTransport();
        try (Client client = Client.builder("test-key")
                .transport(transport)
                .batchSize(25) // deliberately far above 1 — this test must not pass "by accident"
                .build()) {
            DevFortressFilter filter = new DevFortressFilter(client);

            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login");
            request.setRemoteAddr("203.0.113.7");
            MockHttpServletResponse response = new MockHttpServletResponse();
            FilterChain chain = (req, res) -> ((MockHttpServletResponse) res).setStatus(401); // auth_failure: classified

            long started = System.nanoTime();
            filter.doFilter(request, response, chain);
            long elapsedMs = (System.nanoTime() - started) / 1_000_000;

            assertTrue(elapsedMs < 200, "the filter must not block the response on delivery (took " + elapsedMs + "ms)");

            waitUntil(() -> transport.callCount() >= 1, Duration.ofSeconds(2));
            assertEquals(1, transport.callCount(),
                    "a single sparse request must be delivered by the real filter, not held for batch size 25");
            assertEquals(0, client.pendingEvents());
        }
    }

    @Test
    void excludedPathsAreNeverReported() throws Exception {
        RecordingTransport transport = new RecordingTransport();
        try (Client client = Client.builder("test-key").transport(transport).build()) {
            DevFortressFilter filter = new DevFortressFilter(client);

            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/health");
            MockHttpServletResponse response = new MockHttpServletResponse();
            FilterChain chain = (req, res) -> ((MockHttpServletResponse) res).setStatus(200);

            filter.doFilter(request, response, chain);
            TimeUnit.MILLISECONDS.sleep(200);
            assertEquals(0, transport.callCount());
        }
    }

    @Test
    void aHandlerExceptionStillPropagatesAndIsStillReported() {
        RecordingTransport transport = new RecordingTransport();
        AtomicInteger chainCalls = new AtomicInteger();
        try (Client client = Client.builder("test-key").transport(transport).build()) {
            DevFortressFilter filter = new DevFortressFilter(client);

            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/boom");
            MockHttpServletResponse response = new MockHttpServletResponse();
            FilterChain chain = (req, res) -> {
                chainCalls.incrementAndGet();
                ((MockHttpServletResponse) res).setStatus(500);
                throw new RuntimeException("handler blew up");
            };

            RuntimeException thrown = org.junit.jupiter.api.Assertions.assertThrows(RuntimeException.class,
                    () -> filter.doFilter(request, response, chain));
            assertEquals("handler blew up", thrown.getMessage(), "the filter must not swallow the handler's own exception");
            assertEquals(1, chainCalls.get());

            try {
                waitUntilUnchecked(() -> transport.callCount() >= 1, Duration.ofSeconds(2));
            } catch (AssertionError ignored) {
                // Reporting failing to happen here would itself be a bug worth seeing...
                throw ignored;
            }
            assertEquals(1, transport.callCount(), "the 500 must still be reported even though the handler threw");
        }
    }

    private static void waitUntil(java.util.function.BooleanSupplier condition, Duration timeout) throws InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("condition not met within " + timeout);
            }
            TimeUnit.MILLISECONDS.sleep(10);
        }
    }

    private static void waitUntilUnchecked(java.util.function.BooleanSupplier condition, Duration timeout) {
        try {
            waitUntil(condition, timeout);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
}
