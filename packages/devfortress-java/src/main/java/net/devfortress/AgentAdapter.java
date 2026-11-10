package net.devfortress;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * DevFortress Agent Security Adapter (IP-C1). Mirrors
 * {@code packages/devfortress-sdk/src/agent.ts}'s {@code AgentAdapter}.
 *
 * <p>Unlike the Node SDK's synchronous {@code df.observe()} (which can
 * return a server-decided flagged verdict on the same call), this
 * external-mode {@link Client} queues events ({@link Client#trackEvent}/
 * {@link Client#flush}) with no per-call server round trip to carry a
 * flagged verdict back — so this adapter has no {@code onFlagged} callback,
 * matching the Go/Ruby/PHP/.NET SDKs' same adaptation for the same reason.
 * The event shape (agent_id, tool_name, input_summary, framework, session
 * tracking) matches the Node SDK field-for-field.
 */
public final class AgentAdapter {
    private static final int MAX_TRACKED_SESSIONS = 10_000;

    private final Client client;
    private final String agentId;
    private final String agentName;
    private final String agentIp;
    private final int maxInputSummaryLength;
    private final boolean sanitizeInputs;
    private final Map<String, Integer> sessionToolCounts = new LinkedHashMap<>();
    private final List<String> sessionOrder = new ArrayList<>();
    private final Object lock = new Object();

    public AgentAdapter(Client client, String agentId) {
        this(client, agentId, null, "127.0.0.1", 256, true);
    }

    public AgentAdapter(Client client, String agentId, String agentName, String agentIp,
                         int maxInputSummaryLength, boolean sanitizeInputs) {
        AgentId.validate(agentId);
        this.client = client;
        this.agentId = agentId;
        this.agentName = agentName != null ? agentName : agentId;
        this.agentIp = agentIp != null ? agentIp : "127.0.0.1";
        this.maxInputSummaryLength = maxInputSummaryLength;
        this.sanitizeInputs = sanitizeInputs;
    }

    /** One AI agent tool invocation to observe. Build with the setters you need; {@code tool} is required. */
    public static final class ToolCall {
        final String tool;
        Map<String, Object> input;
        Integer durationMs;
        String model;
        String framework = "custom";
        Map<String, Object> meta;

        public ToolCall(String tool) {
            this.tool = tool;
        }

        public ToolCall input(Map<String, Object> input) {
            this.input = input;
            return this;
        }

        public ToolCall durationMs(Integer durationMs) {
            this.durationMs = durationMs;
            return this;
        }

        public ToolCall model(String model) {
            this.model = model;
            return this;
        }

        public ToolCall framework(String framework) {
            this.framework = framework;
            return this;
        }

        public ToolCall meta(Map<String, Object> meta) {
            this.meta = meta;
            return this;
        }
    }

    /** Queue an observation of an AI agent tool invocation. The real tool inputs stay local — only the summary is transmitted. */
    public void observeToolCall(ToolCall toolCall) {
        observeToolCall(toolCall, null);
    }

    public void observeToolCall(ToolCall toolCall, String sessionId) {
        String summary = summarizeInput(toolCall.input);

        String sid = sessionId != null ? sessionId : "default";
        int count;
        synchronized (lock) {
            count = sessionToolCounts.getOrDefault(sid, 0) + 1;
            sessionToolCounts.put(sid, count);
            if (!sessionOrder.contains(sid)) {
                sessionOrder.add(sid);
            }
        }

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("agent_id", agentId);
        metadata.put("agent_name", agentName);
        metadata.put("tool_name", toolCall.tool);
        metadata.put("input_summary", summary);
        metadata.put("duration_ms", toolCall.durationMs);
        metadata.put("model", toolCall.model);
        metadata.put("framework", toolCall.framework);
        metadata.put("session_tool_count", count);
        metadata.put("session_id", sessionId);
        metadata.put("event_category", "agent_tool_call");
        if (toolCall.meta != null) {
            metadata.putAll(toolCall.meta);
        }

        Map<String, Object> event = new LinkedHashMap<>();
        event.put("eventType", "custom");
        event.put("method", "TOOL_CALL");
        event.put("path", "/agent/" + agentId + "/tool/" + toolCall.tool);
        event.put("ip", agentIp);
        event.put("userAgent", "DevFortress-Agent/" + agentName);
        event.put("severity", "LOW");
        event.put("metadata", metadata);
        client.trackEvent(event);
    }

    /** Convenience wrapper for a LangChain/LangGraph tool call. */
    public void observeLangChainTool(String toolName, Map<String, Object> toolInput, String sessionId, String model, Integer durationMs) {
        observeToolCall(new ToolCall(toolName).input(toolInput).model(model).durationMs(durationMs).framework("langchain"), sessionId);
    }

    /** Convenience wrapper extracting from an OpenAI tool_calls entry. */
    @SuppressWarnings("unchecked")
    public void observeOpenAiToolCall(String functionName, String argumentsJson, String sessionId, String model, Integer durationMs) {
        Map<String, Object> parsed;
        try {
            parsed = (Map<String, Object>) Json.decode(argumentsJson);
        } catch (RuntimeException e) {
            parsed = new LinkedHashMap<>();
            parsed.put("raw", argumentsJson);
        }
        observeToolCall(new ToolCall(functionName).input(parsed).model(model).durationMs(durationMs).framework("openai"), sessionId);
    }

    /** Observe a raw HTTP tool call (e.g. an agent calling an external API). */
    public void observeHttpToolCall(String url, String method, Integer statusCode, Integer durationMs, String sessionId, Map<String, Object> meta) {
        Map<String, Object> input = new LinkedHashMap<>();
        input.put("url", url);
        input.put("status_code", statusCode);
        observeToolCall(new ToolCall("http:" + method.toUpperCase()).input(input).durationMs(durationMs).framework("raw_http").meta(meta), sessionId);
    }

    /** Track the start of an agent session (task/conversation). */
    public void trackSessionStart(String sessionId, String taskDescription) {
        synchronized (lock) {
            if (sessionToolCounts.size() >= MAX_TRACKED_SESSIONS && !sessionOrder.isEmpty()) {
                String oldest = sessionOrder.remove(0);
                sessionToolCounts.remove(oldest);
            }
            sessionToolCounts.put(sessionId, 0);
            sessionOrder.add(sessionId);
        }

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("agent_id", agentId);
        metadata.put("session_id", sessionId);
        metadata.put("task_description", taskDescription);
        metadata.put("event_category", "agent_session_start");

        Map<String, Object> event = new LinkedHashMap<>();
        event.put("eventType", "custom");
        event.put("method", "SESSION_START");
        event.put("path", "/agent/" + agentId + "/session/" + sessionId);
        event.put("ip", agentIp);
        event.put("userAgent", "DevFortress-Agent/" + agentName);
        event.put("severity", "LOW");
        event.put("metadata", metadata);
        client.trackEvent(event);
    }

    /** Track the end of an agent session with summary metrics. */
    public void trackSessionEnd(String sessionId, Integer totalTools, Integer durationMs, Boolean success) {
        int toolCount;
        synchronized (lock) {
            toolCount = sessionToolCounts.getOrDefault(sessionId, 0);
            sessionToolCounts.remove(sessionId);
            sessionOrder.remove(sessionId);
        }

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("agent_id", agentId);
        metadata.put("session_id", sessionId);
        metadata.put("total_tools", totalTools != null ? totalTools : toolCount);
        metadata.put("total_duration_ms", durationMs);
        metadata.put("success", success);
        metadata.put("event_category", "agent_session_end");

        Map<String, Object> event = new LinkedHashMap<>();
        event.put("eventType", "custom");
        event.put("method", "SESSION_END");
        event.put("path", "/agent/" + agentId + "/session/" + sessionId);
        event.put("ip", agentIp);
        event.put("userAgent", "DevFortress-Agent/" + agentName);
        event.put("severity", "LOW");
        event.put("metadata", metadata);
        client.trackEvent(event);
    }

    /** Get the current session tool count for monitoring. */
    public int getSessionToolCount(String sessionId) {
        synchronized (lock) {
            return sessionToolCounts.getOrDefault(sessionId, 0);
        }
    }

    private String summarizeInput(Map<String, Object> input) {
        if (input == null) {
            return "{}";
        }
        Map<String, String> summary = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : input.entrySet()) {
            String key = entry.getKey();
            Object val = entry.getValue();
            if (val == null) {
                summary.put(key, "null");
            } else if (val instanceof String s) {
                summary.put(key, sanitizeInputs && isSensitiveKey(key) ? "[REDACTED]" : (s.length() > 64 ? s.substring(0, 61) + "..." : s));
            } else if (val instanceof Boolean || val instanceof Number) {
                summary.put(key, String.valueOf(val));
            } else if (val instanceof Collection<?> c) {
                summary.put(key, "Array(" + c.size() + ")");
            } else if (val.getClass().isArray()) {
                summary.put(key, "Array(" + java.lang.reflect.Array.getLength(val) + ")");
            } else {
                summary.put(key, "{...}");
            }
        }
        String str = Json.encode(summary);
        return str.length() > maxInputSummaryLength ? str.substring(0, maxInputSummaryLength - 3) + "..." : str;
    }

    private static boolean isSensitiveKey(String key) {
        String lower = key.toLowerCase();
        return lower.contains("key") || lower.contains("token") || lower.contains("secret") || lower.contains("password");
    }
}
