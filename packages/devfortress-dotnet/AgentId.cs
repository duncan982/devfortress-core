using System.Text.RegularExpressions;

namespace DevFortress;

/// <summary>Validates agent IDs for safe use as cache keys and pseudo-URL path segments. Mirrors agent.ts's validateAgentId.</summary>
public static class AgentId
{
    public const int MaxLength = 128;
    private static readonly Regex Pattern = new("^[a-zA-Z0-9_\\-.:@]+$", RegexOptions.Compiled);

    public static void Validate(string agentId)
    {
        if (string.IsNullOrEmpty(agentId))
        {
            throw new ArgumentException("agentId is required and must be a non-empty string", nameof(agentId));
        }
        if (agentId.Length > MaxLength)
        {
            throw new ArgumentException($"agentId must be at most {MaxLength} characters", nameof(agentId));
        }
        if (!Pattern.IsMatch(agentId))
        {
            throw new ArgumentException(
                "agentId may only contain alphanumeric characters, hyphens, underscores, dots, colons, and @", nameof(agentId));
        }
    }
}
