using System.Text.RegularExpressions;

namespace DevFortress;

/// <summary>
/// A16: Prompt Injection Filter. Mirrors the <c>PromptInjectionFilter</c> class in
/// <c>packages/devfortress-sdk/src/security-extensions.ts</c>. Weighted-pattern scoring against
/// known indirect prompt-injection phrasings.
/// </summary>
public enum PromptInjectionSeverity { Low, Medium, High, Critical }

public sealed record PromptInjectionResult(bool Safe, double Confidence, PromptInjectionSeverity Severity,
    IReadOnlyList<string> DetectedPatterns, string Reason);

public sealed class PromptInjectionFilter
{
    private static readonly (string Pattern, string Name, int Weight)[] InjectionPatterns =
    [
        ("ignore\\s+(previous|above|all|prior)\\s+(instructions?|context|rules?)", "instruction_override", 40),
        ("you\\s+are\\s+now\\s+(a|an|the)", "role_assignment", 35),
        ("system\\s*:\\s*|\\[SYSTEM\\]|<\\|system\\|>", "system_prompt_injection", 45),
        ("forget\\s+(everything|all|what)", "memory_wipe", 40),
        ("do\\s+not\\s+(follow|obey|listen)", "disobedience_injection", 35),
        ("act\\s+as\\s+(if|though)|pretend\\s+(to\\s+be|you)", "persona_injection", 30),
        ("<script>|javascript:|onerror=|onload=", "xss_in_data", 50),
        ("\\bexec\\s*\\(|eval\\s*\\(|__import__", "code_execution", 50),
        ("translate.*to.*base64|encode.*payload", "encoding_evasion", 25),
        ("reveal\\s+(your|the)\\s+(system|secret|api|key|password)", "secret_extraction", 45),
    ];

    private readonly List<(Regex Regex, string Name, int Weight)> _patterns = [];
    private readonly int _maxScanLength;
    private readonly double _sensitivityMultiplier;

    public PromptInjectionFilter(string sensitivity = "medium", IReadOnlyList<string>? customPatterns = null, int maxScanLength = 100_000)
    {
        _maxScanLength = maxScanLength;
        _sensitivityMultiplier = sensitivity switch { "high" => 1.5, "low" => 0.7, _ => 1.0 };

        foreach (var (pattern, name, weight) in InjectionPatterns)
        {
            _patterns.Add((new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled), name, weight));
        }
        if (customPatterns is not null)
        {
            for (int i = 0; i < customPatterns.Count; i++)
            {
                _patterns.Add((new Regex(customPatterns[i], RegexOptions.IgnoreCase | RegexOptions.Compiled), $"custom_{i}", 30));
            }
        }
    }

    public PromptInjectionResult ScanAgentInput(string content) => Scan(content);

    public PromptInjectionResult Scan(string content)
    {
        string text = content.Length > _maxScanLength ? content[.._maxScanLength] : content;
        var detectedPatterns = new List<string>();
        int totalWeight = 0;

        foreach (var (regex, name, weight) in _patterns)
        {
            if (regex.IsMatch(text))
            {
                detectedPatterns.Add(name);
                totalWeight += weight;
            }
        }

        int score = Math.Min(100, (int)Math.Round(totalWeight * _sensitivityMultiplier, MidpointRounding.AwayFromZero));
        double confidence = detectedPatterns.Count > 0 ? Math.Min(0.99, 0.5 + detectedPatterns.Count * 0.15) : 0.1;

        var severity = score >= 70 ? PromptInjectionSeverity.Critical
            : score >= 45 ? PromptInjectionSeverity.High
            : score >= 20 ? PromptInjectionSeverity.Medium
            : PromptInjectionSeverity.Low;

        return new PromptInjectionResult(
            score < 30, confidence, severity, detectedPatterns,
            detectedPatterns.Count > 0
                ? $"Prompt injection detected: {string.Join(", ", detectedPatterns)} (score={score})"
                : "Content appears safe");
    }
}
