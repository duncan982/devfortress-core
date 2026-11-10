package net.devfortress;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;

/** Test-only {@link Transport} that records every call and plays back scripted responses/failures. */
final class RecordingTransport implements Transport {
    record Call(String method, String url, Map<String, String> headers, byte[] body) {
    }

    final List<Call> calls = new CopyOnWriteArrayList<>();
    private final Deque<Callable<TransportResponse>> script = new ArrayDeque<>();

    RecordingTransport respond(int statusCode, String body) {
        script.add(() -> new TransportResponse(statusCode, body.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        return this;
    }

    RecordingTransport fail(Exception e) {
        script.add(() -> {
            throw e;
        });
        return this;
    }

    @Override
    public TransportResponse send(String method, String rawUrl, Map<String, String> headers, byte[] body, Duration timeout)
            throws Exception {
        calls.add(new Call(method, rawUrl, headers, body));
        Callable<TransportResponse> next = script.pollFirst();
        if (next == null) {
            return new TransportResponse(200, "{}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }
        return next.call();
    }

    int callCount() {
        return calls.size();
    }
}
