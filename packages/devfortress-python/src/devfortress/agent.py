"""DevFortress Agent Security Adapter.

Port of the Node SDK's ``agent.ts``. Wraps the event client for AI agent
tool invocations. Intercepts agent_id, tool_name, and input_summary from
LangChain/LangGraph, OpenAI function calling, and raw HTTP-based agent tool
invocations.

Scoping note (Python port): Node's ``AgentAdapter.observeToolCall()``
delegates to ``DevFortress.observe()``, whose ``flagged``/``confidence``
fields are computed by a large, separate client-side ML/tier-gate pipeline
(``ml-classifier.ts``, ``tier-gate.ts``, license/quota machinery) — that
pipeline is shared infrastructure used by every event type, not part of
this package's agent-security pillars (credential aliasing, behavioral
fingerprinting, closed-loop response), and is out of scope here. Python's
``observe_tool_call()`` reports the event through the existing signed
ingest path (``DevFortressClient.track_event``) and returns the real
``event_id`` the platform assigns; ``flagged``/``confidence`` are always
``False``/``0.0`` — they do not fabricate a classification Python has no
engine to produce. A caller that wants a tool call blocked locally should
rely on the other pillars (``ToolCallSequenceValidator``, ``AgentAnomalyDetector``,
``AgentScopeEnforcer``, ``AgentLoopDetector``), exactly as the reference
demo's gate chain does before it ever calls ``observe_tool_call()``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional

from .client import DevFortressClient

AGENT_ID_MAX_LENGTH = 128
_AGENT_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-.:@]+$")

_MAX_TRACKED_SESSIONS = 10_000


def validate_agent_id(agent_id: str) -> None:
    """Validate agent ID to prevent injection and ensure safe usage as
    cache keys and pseudo-URL path segments."""
    if not agent_id or not isinstance(agent_id, str):
        raise ValueError("agent_id is required and must be a non-empty string")
    if len(agent_id) > AGENT_ID_MAX_LENGTH:
        raise ValueError(f"agent_id must be at most {AGENT_ID_MAX_LENGTH} characters")
    if not _AGENT_ID_PATTERN.match(agent_id):
        raise ValueError(
            "agent_id may only contain alphanumeric characters, hyphens, underscores, "
            "dots, colons, and @"
        )


@dataclass
class ObserveResult:
    flagged: bool
    event_id: str
    confidence: float


@dataclass
class AgentToolCall:
    tool: str
    input: Optional[Dict[str, Any]] = None
    output: Any = None
    duration_ms: Optional[float] = None
    model: Optional[str] = None
    framework: str = "custom"
    meta: Optional[Dict[str, Any]] = None


def _safe_track_event(client: DevFortressClient, event: Dict[str, Any]) -> "ObserveResult":
    """Matches Node's observe()'s outer try/catch exactly: a delivery failure
    (network error, 5xx after retries, etc.) is logged and never propagates
    to the caller — observation must never break the agent. Returns a
    non-flagged result on failure, same as Node returning null (callers here
    treat an unflagged result identically to None for gating purposes)."""
    try:
        response = client.track_event(event)
        event_id = response.get("event_id") or response.get("eventId") or ""
        return ObserveResult(flagged=False, event_id=event_id, confidence=0.0)
    except Exception as error:
        print(f"[DevFortress] observe() failed: {error}")  # noqa: T201
        return ObserveResult(flagged=False, event_id="", confidence=0.0)


def _summarize_input(
    input_data: Optional[Dict[str, Any]], max_len: int, sanitize: bool
) -> str:
    if not input_data:
        return "{}"
    summary: Dict[str, str] = {}
    for key, val in input_data.items():
        if val is None:
            summary[key] = "null"
        elif isinstance(val, str):
            lowered = key.lower()
            if sanitize and any(s in lowered for s in ("key", "token", "secret", "password")):
                summary[key] = "[REDACTED]"
            else:
                summary[key] = val if len(val) <= 64 else val[:61] + "..."
        elif isinstance(val, bool):
            summary[key] = "true" if val else "false"
        elif isinstance(val, (int, float)):
            summary[key] = str(val)
        elif isinstance(val, list):
            summary[key] = f"Array({len(val)})"
        else:
            summary[key] = "{...}"

    text = json.dumps(summary)
    return text if len(text) <= max_len else text[: max_len - 3] + "..."


class AgentAdapter:
    def __init__(
        self,
        client: DevFortressClient,
        agent_id: str,
        *,
        agent_name: Optional[str] = None,
        agent_ip: str = "127.0.0.1",
        max_input_summary_length: int = 256,
        sanitize_inputs: bool = True,
        on_flagged: Optional[Any] = None,
    ):
        validate_agent_id(agent_id)
        self._client = client
        self._agent_id = agent_id
        self._agent_name = agent_name or agent_id
        self._agent_ip = agent_ip
        self._max_input_summary_length = max_input_summary_length
        self._sanitize_inputs = sanitize_inputs
        self._on_flagged = on_flagged
        self._session_tool_counts: "Dict[str, int]" = {}

    async def observe_tool_call(
        self, tool_call: AgentToolCall, session_id: Optional[str] = None
    ) -> Optional[ObserveResult]:
        """Observe an AI agent tool invocation through DevFortress.

        Extracts agent_id, tool_name, input_summary and sends as a
        structured event. The real tool inputs stay local — only the
        summary is transmitted. See module docstring for the
        flagged/confidence scoping note.
        """
        input_summary = _summarize_input(
            tool_call.input, self._max_input_summary_length, self._sanitize_inputs
        )

        sid = session_id or "default"
        count = self._session_tool_counts.get(sid, 0) + 1
        self._session_tool_counts[sid] = count

        event = {
            "eventType": "custom",
            "ip": self._agent_ip,
            "method": "TOOL_CALL",
            "path": f"/agent/{self._agent_id}/tool/{tool_call.tool}",
            "userAgent": f"DevFortress-Agent/{self._agent_name}",
            "severity": "LOW",
            "clMode": "external",
            "authPhase": "post_auth",
            "actionTaken": "monitored",
            "responseLatencyMs": tool_call.duration_ms or 0,
            "isAgent": True,
            "agentId": self._agent_id,
            "metadata": {
                "agent_id": self._agent_id,
                "agent_name": self._agent_name,
                "tool_name": tool_call.tool,
                "input_summary": input_summary,
                "duration_ms": tool_call.duration_ms,
                "model": tool_call.model,
                "framework": tool_call.framework,
                "session_tool_count": count,
                "session_id": session_id,
                "event_category": "agent_tool_call",
                **(tool_call.meta or {}),
            },
        }

        result = _safe_track_event(self._client, event)

        if result.flagged and self._on_flagged:
            maybe_awaitable = self._on_flagged(tool_call, result)
            if maybe_awaitable is not None:
                await maybe_awaitable

        return result

    async def observe_langchain_tool(
        self,
        tool_name: str,
        tool_input: Dict[str, Any],
        *,
        session_id: Optional[str] = None,
        model: Optional[str] = None,
        duration_ms: Optional[float] = None,
    ) -> Optional[ObserveResult]:
        return await self.observe_tool_call(
            AgentToolCall(
                tool=tool_name,
                input=tool_input,
                framework="langchain",
                model=model,
                duration_ms=duration_ms,
            ),
            session_id,
        )

    async def observe_openai_tool_call(
        self,
        function_name: str,
        arguments_json: str,
        *,
        session_id: Optional[str] = None,
        model: Optional[str] = None,
        duration_ms: Optional[float] = None,
    ) -> Optional[ObserveResult]:
        try:
            parsed_args = json.loads(arguments_json)
        except Exception:
            parsed_args = {"raw": arguments_json}

        return await self.observe_tool_call(
            AgentToolCall(
                tool=function_name,
                input=parsed_args,
                framework="openai",
                model=model,
                duration_ms=duration_ms,
            ),
            session_id,
        )

    async def observe_http_tool_call(
        self,
        url: str,
        method: str,
        *,
        status_code: Optional[int] = None,
        duration_ms: Optional[float] = None,
        session_id: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> Optional[ObserveResult]:
        return await self.observe_tool_call(
            AgentToolCall(
                tool=f"http:{method.upper()}",
                input={"url": url, "status_code": status_code},
                framework="raw_http",
                duration_ms=duration_ms,
                meta=meta,
            ),
            session_id,
        )

    async def track_session_start(
        self, session_id: str, task_description: Optional[str] = None
    ) -> Optional[ObserveResult]:
        if len(self._session_tool_counts) >= _MAX_TRACKED_SESSIONS:
            first = next(iter(self._session_tool_counts), None)
            if first is not None:
                del self._session_tool_counts[first]
        self._session_tool_counts[session_id] = 0

        event = {
            "eventType": "custom",
            "ip": self._agent_ip,
            "method": "SESSION_START",
            "path": f"/agent/{self._agent_id}/session/{session_id}",
            "userAgent": f"DevFortress-Agent/{self._agent_name}",
            "severity": "LOW",
            "clMode": "external",
            "authPhase": "post_auth",
            "actionTaken": "monitored",
            "responseLatencyMs": 0,
            "isAgent": True,
            "agentId": self._agent_id,
            "metadata": {
                "agent_id": self._agent_id,
                "session_id": session_id,
                "task_description": task_description,
                "event_category": "agent_session_start",
            },
        }
        return _safe_track_event(self._client, event)

    async def track_session_end(
        self,
        session_id: str,
        *,
        total_tools: Optional[int] = None,
        duration_ms: Optional[float] = None,
        success: Optional[bool] = None,
    ) -> Optional[ObserveResult]:
        tool_count = self._session_tool_counts.pop(session_id, 0)

        event = {
            "eventType": "custom",
            "ip": self._agent_ip,
            "method": "SESSION_END",
            "path": f"/agent/{self._agent_id}/session/{session_id}",
            "userAgent": f"DevFortress-Agent/{self._agent_name}",
            "severity": "LOW",
            "clMode": "external",
            "authPhase": "post_auth",
            "actionTaken": "monitored",
            "responseLatencyMs": 0,
            "isAgent": True,
            "agentId": self._agent_id,
            "metadata": {
                "agent_id": self._agent_id,
                "session_id": session_id,
                "total_tools": total_tools if total_tools is not None else tool_count,
                "total_duration_ms": duration_ms,
                "success": success,
                "event_category": "agent_session_end",
            },
        }
        return _safe_track_event(self._client, event)

    def get_session_tool_count(self, session_id: str) -> int:
        return self._session_tool_counts.get(session_id, 0)
