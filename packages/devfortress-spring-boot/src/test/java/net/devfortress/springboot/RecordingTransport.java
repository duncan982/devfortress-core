package net.devfortress.springboot;

import net.devfortress.Transport;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/** Test-only {@link Transport} that records every call. Mirrors devfortress-sdk's own test helper of the same name. */
final class RecordingTransport implements Transport {
    final List<byte[]> bodies = new CopyOnWriteArrayList<>();
    private final java.util.concurrent.atomic.AtomicInteger count = new java.util.concurrent.atomic.AtomicInteger();

    @Override
    public TransportResponse send(String method, String rawUrl, Map<String, String> headers, byte[] body, Duration timeout) {
        count.incrementAndGet();
        bodies.add(body);
        return new TransportResponse(200, "{}".getBytes(StandardCharsets.UTF_8));
    }

    int callCount() {
        return count.get();
    }
}
