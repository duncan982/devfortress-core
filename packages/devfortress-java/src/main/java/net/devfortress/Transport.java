package net.devfortress;

import java.time.Duration;
import java.util.Map;

/**
 * Sends one HTTP request and returns the response. The URL and the
 * header/body bytes must go on the wire exactly as given: the request
 * signature covers them. Implementations throw only on a network-level
 * failure (no HTTP response); an HTTP error status is a normal
 * {@link TransportResponse}. Swappable in tests (a recording transport).
 */
public interface Transport {
    TransportResponse send(String method, String rawUrl, Map<String, String> headers, byte[] body, Duration timeout)
            throws Exception;

    record TransportResponse(int statusCode, byte[] body) {
    }
}
