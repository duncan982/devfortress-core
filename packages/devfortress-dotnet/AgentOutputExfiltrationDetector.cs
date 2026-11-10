using System.Text;
using System.Text.RegularExpressions;

namespace DevFortress;

/// <summary>
/// Agent Output Exfiltration Detector. Mirrors
/// <c>packages/devfortress-sdk/src/agent-output-exfiltration-detector.ts</c>. Monitors AI agent
/// outputs for potential data exfiltration patterns. Detects when agent responses contain
/// sensitive data that shouldn't be included in outputs (PII, credentials, internal system
/// info).
/// </summary>
/// <remarks>
/// Node ships this pillar flag-gated only (<c>process.env.FEATURE_PLATFORM_INTEL</c>), in the
/// publicly-shipped part of the npm package. Every prior language port (Go, Ruby, PHP, Java)
/// chose to drop that runtime flag and rely on nothing but public visibility instead — this
/// port does the same, matching Node's public-with-disclosure posture.
/// Patent Pending.
/// </remarks>
public enum AgentOutputType { Text, Json, Code, File }

public enum OutputDestinationType { User, Api, File, Log }

public enum ExfiltrationThreatType { PiiLeak, CredentialLeak, SystemInfoLeak, HighEntropySecret, OversizedOutput, None }

public enum ExfiltrationRecommendation { Block, Redact, Warn, Allow }

public sealed record AgentOutput(string AgentId, string OutputContent, AgentOutputType OutputType,
    OutputDestinationType DestinationType, long Timestamp);

public sealed record ExfiltrationResult(bool Detected, ExfiltrationThreatType ThreatType, double Confidence,
    IReadOnlyList<string> MatchedPatterns, ExfiltrationRecommendation Recommendation, string? RedactedOutput = null);

public sealed record ExfiltrationDetectorConfig(
    IReadOnlyList<string>? SensitivePatterns = null,
    int MaxOutputSizeBytes = 1_048_576,
    bool EntropyDetection = true,
    double EntropyThreshold = 4.5);

public sealed class AgentOutputExfiltrationDetector
{
    public static readonly IReadOnlyList<string> DefaultSensitivePatterns =
    [
        // Credit cards
        @"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
        // SSN
        @"\b\d{3}-\d{2}-\d{4}\b",
        // Email addresses in unexpected contexts
        @"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b",
        // API keys / tokens (high entropy strings)
        @"(?:api[_-]?key|token|secret|password|credential)[\s:=]+[""']?[A-Za-z0-9+/=_-]{20,}[""']?",
        // AWS keys
        @"(?:AKIA|ASIA)[A-Z0-9]{16}",
        // Private keys
        @"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
        // Internal IPs
        @"\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[0-9.]+\b",
    ];

    private static readonly Regex CandidateSegmentPattern = new(@"[A-Za-z0-9+/=_-]{32,}", RegexOptions.Compiled);

    private readonly ExfiltrationDetectorConfig _config;
    private readonly IReadOnlyList<string> _sensitivePatterns;
    private readonly List<Regex> _compiledPatterns;

    public AgentOutputExfiltrationDetector(ExfiltrationDetectorConfig? config = null)
    {
        _config = config ?? new ExfiltrationDetectorConfig();
        _sensitivePatterns = _config.SensitivePatterns ?? DefaultSensitivePatterns;
        _compiledPatterns = [.. _sensitivePatterns.Select(p => new Regex(p, RegexOptions.IgnoreCase | RegexOptions.Compiled))];
    }

    public ExfiltrationResult Analyze(AgentOutput output)
    {
        // Check output size (UTF-8 byte length, matching Node's Buffer.byteLength).
        if (Encoding.UTF8.GetByteCount(output.OutputContent) > _config.MaxOutputSizeBytes)
        {
            return new ExfiltrationResult(true, ExfiltrationThreatType.OversizedOutput, 0.7, [], ExfiltrationRecommendation.Warn);
        }

        // Pattern matching.
        var matchedPatterns = new List<string>();
        for (int i = 0; i < _compiledPatterns.Count; i++)
        {
            if (_compiledPatterns[i].IsMatch(output.OutputContent))
            {
                matchedPatterns.Add(_sensitivePatterns[i]);
            }
        }

        if (matchedPatterns.Count > 0)
        {
            // Node checks for the literal substrings "SSN"/"credit" inside the pattern STRING
            // itself, not inside whatever it matched. Neither substring ever appears in
            // DEFAULT_SENSITIVE_PATTERNS's actual regex text (only in a // comment above each
            // entry, which isn't part of the string) — so with the default pattern set, the
            // pii-leak branch is dead code and anything other than a PRIVATE KEY/AKIA match
            // classifies as system-info-leak. Ported faithfully: a caller supplying custom
            // patterns whose text happens to contain "SSN" or "credit" would still reach
            // pii-leak, exactly as in Node.
            var threatType = matchedPatterns.Any(p => p.Contains("PRIVATE KEY") || p.Contains("AKIA"))
                ? ExfiltrationThreatType.CredentialLeak
                : matchedPatterns.Any(p => p.Contains("SSN") || p.Contains("credit"))
                    ? ExfiltrationThreatType.PiiLeak
                    : ExfiltrationThreatType.SystemInfoLeak;

            return new ExfiltrationResult(
                true,
                threatType,
                Math.Min(1, 0.5 + matchedPatterns.Count * 0.15),
                matchedPatterns,
                threatType == ExfiltrationThreatType.CredentialLeak ? ExfiltrationRecommendation.Block : ExfiltrationRecommendation.Redact,
                Redact(output.OutputContent));
        }

        // Entropy detection for unknown secrets.
        if (_config.EntropyDetection)
        {
            var highEntropySegments = FindHighEntropySegments(output.OutputContent);
            if (highEntropySegments.Count > 0)
            {
                return new ExfiltrationResult(true, ExfiltrationThreatType.HighEntropySecret, 0.6, highEntropySegments,
                    ExfiltrationRecommendation.Warn);
            }
        }

        return new ExfiltrationResult(false, ExfiltrationThreatType.None, 0, [], ExfiltrationRecommendation.Allow);
    }

    private string Redact(string content)
    {
        string redacted = content;
        foreach (var pattern in _compiledPatterns)
        {
            redacted = pattern.Replace(redacted, "[REDACTED]");
        }
        return redacted;
    }

    private List<string> FindHighEntropySegments(string content)
    {
        var segments = new List<string>();
        foreach (Match candidate in CandidateSegmentPattern.Matches(content))
        {
            if (ShannonEntropy(candidate.Value) > _config.EntropyThreshold)
            {
                segments.Add(candidate.Value[..Math.Min(20, candidate.Value.Length)] + "...");
            }
        }
        return segments;
    }

    private static double ShannonEntropy(string str)
    {
        var freq = new Dictionary<char, int>();
        foreach (char c in str)
        {
            freq[c] = freq.GetValueOrDefault(c) + 1;
        }
        int len = str.Length;
        double sum = 0;
        foreach (int count in freq.Values)
        {
            double p = (double)count / len;
            sum += p * Math.Log2(p);
        }
        return -sum;
    }
}
