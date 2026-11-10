package net.devfortress;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * DevFortress SDK — A16: Prompt Injection Filter. Mirrors the
 * {@code PromptInjectionFilter} class in
 * {@code packages/devfortress-sdk/src/security-extensions.ts}.
 *
 * <p>Scans text for known indirect prompt-injection patterns (instruction
 * override, role assignment, system-prompt injection, memory wipe,
 * disobedience injection, persona injection, XSS-in-data, code execution,
 * encoding evasion, secret extraction) and scores a severity band.
 */
public final class PromptInjectionFilter {
    private record PatternSpec(String pattern, String name, int weight) {
    }

    private record CompiledPattern(Pattern regex, String name, int weight) {
    }

    private static final List<PatternSpec> INJECTION_PATTERNS = List.of(
            new PatternSpec("ignore\\s+(previous|above|all|prior)\\s+(instructions?|context|rules?)", "instruction_override", 40),
            new PatternSpec("you\\s+are\\s+now\\s+(a|an|the)", "role_assignment", 35),
            new PatternSpec("system\\s*:\\s*|\\[SYSTEM\\]|<\\|system\\|>", "system_prompt_injection", 45),
            new PatternSpec("forget\\s+(everything|all|what)", "memory_wipe", 40),
            new PatternSpec("do\\s+not\\s+(follow|obey|listen)", "disobedience_injection", 35),
            new PatternSpec("act\\s+as\\s+(if|though)|pretend\\s+(to\\s+be|you)", "persona_injection", 30),
            new PatternSpec("<script>|javascript:|onerror=|onload=", "xss_in_data", 50),
            new PatternSpec("\\bexec\\s*\\(|eval\\s*\\(|__import__", "code_execution", 50),
            new PatternSpec("translate.*to.*base64|encode.*payload", "encoding_evasion", 25),
            new PatternSpec("reveal\\s+(your|the)\\s+(system|secret|api|key|password)", "secret_extraction", 45));

    public enum Sensitivity {
        LOW, MEDIUM, HIGH
    }

    public enum Severity {
        LOW, MEDIUM, HIGH, CRITICAL
    }

    public record Result(boolean safe, double confidence, Severity severity, List<String> detectedPatterns, String reason) {
    }

    private final Sensitivity sensitivity;
    private final int maxScanLength;
    private final List<CompiledPattern> patterns;

    public PromptInjectionFilter() {
        this(Sensitivity.MEDIUM, List.of(), 100_000);
    }

    public PromptInjectionFilter(Sensitivity sensitivity) {
        this(sensitivity, List.of(), 100_000);
    }

    public PromptInjectionFilter(Sensitivity sensitivity, List<String> customPatterns, int maxScanLength) {
        this.sensitivity = sensitivity;
        this.maxScanLength = maxScanLength;
        List<CompiledPattern> compiled = new ArrayList<>();
        for (PatternSpec p : INJECTION_PATTERNS) {
            compiled.add(new CompiledPattern(Pattern.compile(p.pattern(), Pattern.CASE_INSENSITIVE), p.name(), p.weight()));
        }
        for (int i = 0; i < customPatterns.size(); i++) {
            compiled.add(new CompiledPattern(Pattern.compile(customPatterns.get(i), Pattern.CASE_INSENSITIVE), "custom_" + i, 30));
        }
        this.patterns = compiled;
    }

    /** Scan text for indirect prompt-injection patterns. */
    public Result scan(String content) {
        String text = content.length() > maxScanLength ? content.substring(0, maxScanLength) : content;
        List<String> detectedPatterns = new ArrayList<>();
        int totalWeight = 0;

        for (CompiledPattern pattern : patterns) {
            if (pattern.regex().matcher(text).find()) {
                detectedPatterns.add(pattern.name());
                totalWeight += pattern.weight();
            }
        }

        double sensitivityMultiplier = switch (sensitivity) {
            case HIGH -> 1.5;
            case LOW -> 0.7;
            case MEDIUM -> 1.0;
        };

        int score = Math.min(100, (int) Math.round(totalWeight * sensitivityMultiplier));
        double confidence = detectedPatterns.isEmpty() ? 0.1 : Math.min(0.99, 0.5 + detectedPatterns.size() * 0.15);

        Severity severity;
        if (score >= 70) {
            severity = Severity.CRITICAL;
        } else if (score >= 45) {
            severity = Severity.HIGH;
        } else if (score >= 20) {
            severity = Severity.MEDIUM;
        } else {
            severity = Severity.LOW;
        }

        String reason = detectedPatterns.isEmpty()
                ? "Content appears safe"
                : "Prompt injection detected: " + String.join(", ", detectedPatterns) + " (score=" + score + ")";

        return new Result(score < 30, confidence, severity, detectedPatterns, reason);
    }

    /** Convenience alias matching Node's {@code scanAgentInput}. */
    public Result scanAgentInput(String content) {
        return scan(content);
    }
}
