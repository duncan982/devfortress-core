package net.devfortress;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Byte-for-byte against the shared cross-language vectors
 * ({@code contracts/ingest-signature-vectors.json}, repo root — generated
 * by an independent Python script, not by any SDK), the same fixture Go's
 * {@code vectors_test.go} and Ruby's {@code signing_vectors_test.rb} run
 * against. Mirrors Go's split: {@code Verify} is checked against every
 * vector; {@code Sign} byte-for-byte reproduction is only checked for
 * "valid"/"expired" vectors, since every other vector's wire headers were
 * deliberately tampered and so would never match a fresh sign of the same
 * sign_input.
 */
class SignerVectorsTest {
    private static final Path VECTORS_PATH = Path.of("../../contracts/ingest-signature-vectors.json");

    @SuppressWarnings("unchecked")
    private static Map<String, Object> loadVectorFile() throws IOException {
        String text = Files.readString(VECTORS_PATH);
        return (Map<String, Object>) Json.decode(text);
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> vectors() throws IOException {
        Map<String, Object> root = loadVectorFile();
        List<Map<String, Object>> vectors = (List<Map<String, Object>>) (List<?>) root.get("vectors");
        assertTrue(vectors.size() >= 26, "expected at least 26 vectors, got " + vectors.size());
        return vectors;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> wireHeaders(Map<String, Object> vector) {
        Map<String, Object> headers = (Map<String, Object>) vector.get("headers");
        Map<String, String> out = new HashMap<>();
        out.put(Signer.NONCE_HEADER, (String) headers.get("nonce"));
        out.put(Signer.TIMESTAMP_HEADER, (String) headers.get("timestamp"));
        out.put(Signer.PAYLOAD_HASH_HEADER, (String) headers.get("payload_hash"));
        out.put(Signer.SIGNATURE_HEADER, (String) headers.get("signature"));
        out.put(Signer.VERSION_HEADER, (String) headers.get("version"));
        return out;
    }

    @TestFactory
    Stream<DynamicTest> everyVerifierVectorGivesItsExpectedResult() throws IOException {
        return vectors().stream().map(vector -> DynamicTest.dynamicTest((String) vector.get("name"), () -> {
            long nowMs = ((Number) vector.get("now_ms")).longValue();
            Signer.VerifyResult expected = Signer.VerifyResult.valueOf(
                    ((String) vector.get("expected")).toUpperCase());
            Signer.VerifyResult actual = Signer.verify(
                    (String) vector.get("verify_key"), (String) vector.get("method"),
                    (String) vector.get("request_target"), (String) vector.get("body"),
                    wireHeaders(vector), nowMs);
            assertEquals(expected, actual, "verify() mismatch for vector " + vector.get("name"));
        }));
    }

    @SuppressWarnings("unchecked")
    @TestFactory
    Stream<DynamicTest> signingMatchesTheVectorsByteForByte() throws IOException {
        List<DynamicTest> tests = new java.util.ArrayList<>();
        for (Map<String, Object> vector : vectors()) {
            String expected = (String) vector.get("expected");
            Map<String, Object> signIn = (Map<String, Object>) vector.get("sign_input");
            if (signIn == null || !(expected.equals("valid") || expected.equals("expired"))) {
                continue;
            }
            tests.add(DynamicTest.dynamicTest((String) vector.get("name"), () -> {
                Signer signer = new Signer((String) signIn.get("api_key"));
                Map<String, String> signed = signer.sign(
                        (String) signIn.get("method"), (String) signIn.get("request_target"),
                        (String) signIn.get("body"), (String) signIn.get("timestamp"), (String) signIn.get("nonce"));
                Map<String, String> want = wireHeaders(vector);

                assertEquals(want.get(Signer.PAYLOAD_HASH_HEADER).toLowerCase(), signed.get(Signer.PAYLOAD_HASH_HEADER));
                assertEquals(want.get(Signer.SIGNATURE_HEADER).toLowerCase(), signed.get(Signer.SIGNATURE_HEADER));
                assertEquals(want.get(Signer.NONCE_HEADER), signed.get(Signer.NONCE_HEADER));
                assertEquals(want.get(Signer.TIMESTAMP_HEADER), signed.get(Signer.TIMESTAMP_HEADER));
                assertEquals("2", signed.get(Signer.VERSION_HEADER));
            }));
        }
        assertTrue(tests.size() >= 8, "expected at least 8 signed vectors checked, got " + tests.size());
        return tests.stream();
    }

    @Test
    void deriveKeyIdIsFirst32HexCharsOfSha256() {
        String keyId = Signer.deriveKeyId("vx_live_test_vector_key_do_not_use");
        assertEquals(32, keyId.length());
        assertTrue(keyId.matches("^[0-9a-f]{32}$"));
    }

    @Test
    void requestTargetFromUrlStripsSchemeAndHost() {
        assertEquals("/api/events/ingest", Signer.requestTargetFromUrl("https://www.devfortress.net/api/events/ingest"));
        assertEquals("/a/b?x=1&y=2", Signer.requestTargetFromUrl("https://host/a/b?x=1&y=2"));
        assertEquals("/", Signer.requestTargetFromUrl("https://host"));
    }
}
