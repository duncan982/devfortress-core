package net.devfortress;

import java.util.regex.Pattern;

/**
 * Validates agent IDs for safe use as cache keys and pseudo-URL path
 * segments. Mirrors {@code agent.ts}'s {@code validateAgentId}.
 */
public final class AgentId {
    public static final int MAX_LENGTH = 128;
    private static final Pattern PATTERN = Pattern.compile("^[a-zA-Z0-9_\\-.:@]+$");

    private AgentId() {
    }

    public static void validate(String agentId) {
        if (agentId == null || agentId.isEmpty()) {
            throw new IllegalArgumentException("agentId is required and must be a non-empty string");
        }
        if (agentId.length() > MAX_LENGTH) {
            throw new IllegalArgumentException("agentId must be at most " + MAX_LENGTH + " characters");
        }
        if (!PATTERN.matcher(agentId).matches()) {
            throw new IllegalArgumentException(
                    "agentId may only contain alphanumeric characters, hyphens, underscores, dots, colons, and @");
        }
    }
}
