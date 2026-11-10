package net.devfortress;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

/**
 * Default {@link Transport}: the JDK's built-in {@code java.net.http.HttpClient}
 * (Java 11+), HTTP/1.1, no redirects followed (a 3xx is returned to the
 * caller as-is, never re-requested) — matching Go's {@code net/http}-only,
 * Ruby's {@code net/http}-only approach: no new HTTP dependency.
 *
 * <p>{@code rawUrl} is sent to {@link URI#create} as-is rather than built up
 * through a URI builder that could re-encode the path or query — the same
 * endpoint string the {@link Signer} signed is what reaches the wire,
 * matching the guarantee {@code packages/devfortress-go/transport.go}
 * documents and tests for (its own request target survives byte-for-byte,
 * including a gateway prefix or an already-encoded query).
 */
public final class HttpTransport implements Transport {
    private final HttpClient client;

    public HttpTransport() {
        this.client = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    public HttpTransport(HttpClient client) {
        this.client = client;
    }

    @Override
    public TransportResponse send(String method, String rawUrl, Map<String, String> headers, byte[] body,
                                   Duration timeout) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(rawUrl))
                .timeout(timeout);
        for (Map.Entry<String, String> header : headers.entrySet()) {
            builder.header(header.getKey(), header.getValue());
        }
        HttpRequest.BodyPublisher publisher = (body == null || body.length == 0)
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofByteArray(body);
        builder.method(method.toUpperCase(), publisher);

        HttpResponse<byte[]> response = client.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
        return new TransportResponse(response.statusCode(), response.body());
    }
}
