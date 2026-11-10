package net.devfortress;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * DevFortress SDK — Agent Output Exfiltration Detector. Mirrors
 * {@code packages/devfortress-sdk/src/agent-output-exfiltration-detector.ts}.
 *
 * <p>Monitors AI agent outputs for potential data exfiltration patterns.
 * Detects when agent responses contain sensitive data that shouldn't be
 * included in outputs (PII, credentials, internal system info).
 *
 * <p>Audited Node quirk, preserved faithfully (not fixed): the {@code
 * credential-leak} vs. {@code pii-leak} classification below checks each
 * matched pattern's own regex-source text for the literal substrings
 * {@code "PRIVATE KEY"} / {@code "AKIA"} (true for the private-key and AWS-key
 * default patterns) and {@code "SSN"} / {@code "credit"} (which never appear
 * in the default SSN or credit-card regex source, since those are written as
 * {@code \d{3}-\d{2}-\d{4}} and a bare digit-class alternation with no
 * descriptive words at all) — so with the default pattern set, a matched SSN
 * or credit-card number is classified {@code system-info-leak}, never {@code
 * pii-leak}. {@code pii-leak} is only reachable with a caller-supplied custom
 * pattern whose own source text happens to contain one of those words.
 *
 * Patent Pending.
 */
public final class AgentOutputExfiltrationDetector {
    /** Output type being analyzed. */
    public enum OutputType { TEXT, JSON, CODE, FILE }

    /** Where the output is headed. */
    public enum DestinationType { USER, API, FILE, LOG }

    /** Detected threat category. */
    public enum ThreatType {
        PII_LEAK, CREDENTIAL_LEAK, SYSTEM_INFO_LEAK, HIGH_ENTROPY_SECRET, OVERSIZED_OUTPUT, NONE
    }

    /** What to do about a detection. */
    public enum Recommendation { BLOCK, REDACT, WARN, ALLOW }

    /** One agent output to analyze. */
    public record AgentOutput(String agentId, String outputContent, OutputType outputType,
                               DestinationType destinationType, long timestamp) {
    }

    /** Result of {@link #analyze}. */
    public record ExfiltrationResult(boolean detected, ThreatType threatType, double confidence,
                                      List<String> matchedPatterns, Recommendation recommendation,
                                      String redactedOutput) {
    }

    private static final List<String> DEFAULT_SENSITIVE_PATTERNS = List.of(
            // Credit cards
            "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\\b",
            // SSN
            "\\b\\d{3}-\\d{2}-\\d{4}\\b",
            // Email addresses in unexpected contexts
            "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z]{2,}\\b",
            // API keys / tokens (high entropy strings)
            "(?:api[_-]?key|token|secret|password|credential)[\\s:=]+[\"']?[A-Za-z0-9+/=_-]{20,}[\"']?",
            // AWS keys
            "(?:AKIA|ASIA)[A-Z0-9]{16}",
            // Private keys
            "-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
            // Internal IPs
            "\\b(?:10\\.|172\\.(?:1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)[0-9.]+\\b");

    /** Configures a {@link AgentOutputExfiltrationDetector}. */
    public static final class Builder {
        private List<String> sensitivePatterns = DEFAULT_SENSITIVE_PATTERNS;
        private long maxOutputSizeBytes = 1_048_576;
        private boolean entropyDetection = true;
        private double entropyThreshold = 4.5;

        public Builder sensitivePatterns(List<String> sensitivePatterns) {
            this.sensitivePatterns = sensitivePatterns;
            return this;
        }

        public Builder maxOutputSizeBytes(long maxOutputSizeBytes) {
            this.maxOutputSizeBytes = maxOutputSizeBytes;
            return this;
        }

        public Builder entropyDetection(boolean entropyDetection) {
            this.entropyDetection = entropyDetection;
            return this;
        }

        public Builder entropyThreshold(double entropyThreshold) {
            this.entropyThreshold = entropyThreshold;
            return this;
        }

        public AgentOutputExfiltrationDetector build() {
            return new AgentOutputExfiltrationDetector(this);
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    private final List<String> sensitivePatterns;
    private final long maxOutputSizeBytes;
    private final boolean entropyDetection;
    private final double entropyThreshold;
    private final List<Pattern> compiledPatterns;

    public AgentOutputExfiltrationDetector() {
        this(new Builder());
    }

    private AgentOutputExfiltrationDetector(Builder b) {
        this.sensitivePatterns = b.sensitivePatterns;
        this.maxOutputSizeBytes = b.maxOutputSizeBytes;
        this.entropyDetection = b.entropyDetection;
        this.entropyThreshold = b.entropyThreshold;
        this.compiledPatterns = new ArrayList<>(sensitivePatterns.size());
        for (String p : sensitivePatterns) {
            compiledPatterns.add(Pattern.compile(p, Pattern.CASE_INSENSITIVE));
        }
    }

    public ExfiltrationResult analyze(AgentOutput output) {
        if ("false".equals(System.getenv("FEATURE_PLATFORM_INTEL"))) {
            return new ExfiltrationResult(false, ThreatType.NONE, 0, List.of(), Recommendation.ALLOW, null);
        }

        // Check output size
        if (output.outputContent().getBytes(StandardCharsets.UTF_8).length > maxOutputSizeBytes) {
            return new ExfiltrationResult(true, ThreatType.OVERSIZED_OUTPUT, 0.7, List.of(), Recommendation.WARN, null);
        }

        // Pattern matching
        List<String> matchedPatterns = new ArrayList<>();
        for (int i = 0; i < compiledPatterns.size(); i++) {
            Matcher m = compiledPatterns.get(i).matcher(output.outputContent());
            if (m.find()) {
                matchedPatterns.add(sensitivePatterns.get(i));
            }
        }

        if (!matchedPatterns.isEmpty()) {
            boolean looksLikeCredential = matchedPatterns.stream()
                    .anyMatch(p -> p.contains("PRIVATE KEY") || p.contains("AKIA"));
            boolean looksLikePii = matchedPatterns.stream()
                    .anyMatch(p -> p.contains("SSN") || p.contains("credit"));
            ThreatType threatType = looksLikeCredential
                    ? ThreatType.CREDENTIAL_LEAK
                    : looksLikePii ? ThreatType.PII_LEAK : ThreatType.SYSTEM_INFO_LEAK;

            return new ExfiltrationResult(
                    true,
                    threatType,
                    Math.min(1, 0.5 + matchedPatterns.size() * 0.15),
                    matchedPatterns,
                    threatType == ThreatType.CREDENTIAL_LEAK ? Recommendation.BLOCK : Recommendation.REDACT,
                    redact(output.outputContent()));
        }

        // Entropy detection for unknown secrets
        if (entropyDetection) {
            List<String> highEntropySegments = findHighEntropySegments(output.outputContent());
            if (!highEntropySegments.isEmpty()) {
                return new ExfiltrationResult(true, ThreatType.HIGH_ENTROPY_SECRET, 0.6,
                        highEntropySegments, Recommendation.WARN, null);
            }
        }

        return new ExfiltrationResult(false, ThreatType.NONE, 0, List.of(), Recommendation.ALLOW, null);
    }

    private String redact(String content) {
        String redacted = content;
        for (Pattern pattern : compiledPatterns) {
            redacted = pattern.matcher(redacted).replaceAll("[REDACTED]");
        }
        return redacted;
    }

    private static final Pattern HIGH_ENTROPY_CANDIDATE = Pattern.compile("[A-Za-z0-9+/=_-]{32,}");

    private List<String> findHighEntropySegments(String content) {
        List<String> segments = new ArrayList<>();
        Matcher m = HIGH_ENTROPY_CANDIDATE.matcher(content);
        while (m.find()) {
            String candidate = m.group();
            if (shannonEntropy(candidate) > entropyThreshold) {
                segments.add(candidate.substring(0, Math.min(20, candidate.length())) + "...");
            }
        }
        return segments;
    }

    /** Iterates by Unicode code point, matching JS's {@code for (const char of str)} semantics. */
    private static double shannonEntropy(String str) {
        Map<Integer, Integer> freq = new LinkedHashMap<>();
        int len = 0;
        for (int i = 0; i < str.length(); ) {
            int cp = str.codePointAt(i);
            freq.merge(cp, 1, Integer::sum);
            i += Character.charCount(cp);
            len++;
        }
        if (len == 0) {
            return 0;
        }
        double entropy = 0;
        for (int count : freq.values()) {
            double p = (double) count / len;
            entropy += p * (Math.log(p) / Math.log(2));
        }
        return -entropy;
    }
}
