package net.devfortress;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Byte-for-byte against the shared cross-language vectors
 * ({@code contracts/webhook-signature-vectors.json}, repo root).
 */
class WebhookVerifierVectorsTest {
    private static final Path VECTORS_PATH = Path.of("../../contracts/webhook-signature-vectors.json");

    @SuppressWarnings("unchecked")
    @TestFactory
    Stream<DynamicTest> everyVectorMatches() throws IOException {
        String text = Files.readString(VECTORS_PATH);
        Map<String, Object> root = (Map<String, Object>) Json.decode(text);
        List<Map<String, Object>> vectors = (List<Map<String, Object>>) (List<?>) root.get("vectors");
        assertTrue(vectors.size() >= 15, "expected at least 15 vectors, got " + vectors.size());

        return vectors.stream().map(vector -> DynamicTest.dynamicTest((String) vector.get("name"), () -> {
            long nowMs = Instant.parse((String) vector.get("now")).toEpochMilli();
            WebhookVerifier.Options opts = new WebhookVerifier.Options().now(nowMs);

            WebhookVerifier.Result result = WebhookVerifier.verify(
                    (String) vector.get("body"), (String) vector.get("signature"),
                    (String) vector.get("timestamp"), (String) vector.get("secret"), opts);

            boolean expectedValid = (Boolean) vector.get("expected_valid");
            assertEquals(expectedValid, result.valid(), "vector " + vector.get("name") + ": " + result.reason());
        }));
    }
}
