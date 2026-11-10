"""Maps an HTTP response to a DevFortress event, as the Node middleware does."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import unquote_plus

_SQL = [
    re.compile(r"(\bor\b.*=.*)", re.I),
    re.compile(r"(\bunion\b.*\bselect\b)", re.I),
    re.compile(r"(\bdrop\b.*\btable\b)", re.I),
    re.compile(r"('\s*or\s*'1'\s*=\s*'1)", re.I),
]
_XSS = [
    re.compile(r"<script[^>]*>[\s\S]*?</script>", re.I),
    re.compile(r"javascript:", re.I),
    re.compile(r"onerror\s*=\s*", re.I),
    re.compile(r"onload\s*=\s*", re.I),
]
_TRAVERSAL = [re.compile(r"\.\.[/\\]"), re.compile(r"/etc/passwd", re.I)]


def detect_suspicious(text: str) -> List[str]:
    # Match the raw text and one percent-decoding pass.
    candidates = [text]
    decoded = unquote_plus(text)
    if decoded != text:
        candidates.append(decoded)

    def hit(patterns: List["re.Pattern[str]"]) -> bool:
        return any(p.search(c) for c in candidates for p in patterns)

    found = []
    if hit(_SQL):
        found.append("sql_injection")
    if hit(_XSS):
        found.append("xss")
    if hit(_TRAVERSAL):
        found.append("path_traversal")
    return found


def build_event(
    *,
    ip: str,
    method: str,
    path: str,
    status_code: int,
    latency_ms: int,
    user_agent: Optional[str] = None,
    query: str = "",
    user_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Return an event dict, or None when the request isn't security-relevant."""
    event_type = None
    severity = "LOW"
    reason = None
    action = "monitored"

    if status_code in (401, 403):
        event_type, severity, reason = "auth_failure", "MEDIUM", "Authentication or authorization failed"
        action = "blocked"
    elif status_code in (400, 422):
        event_type, reason = "validation_error", "Request validation failed"
    elif status_code == 429:
        event_type, severity, reason = "rate_limit_exceeded", "MEDIUM", "Rate limit exceeded"
        action = "rate_limited"
    elif status_code >= 500:
        event_type, severity, reason = "5xx_error", "HIGH", f"Server error: {status_code}"
    elif status_code >= 400:
        event_type, reason = "4xx_error", f"Client error: {status_code}"

    suspicious = detect_suspicious(f"{path} {query}")
    if suspicious:
        event_type, severity = "suspicious_pattern", "HIGH"
        reason = f"Suspicious patterns detected: {', '.join(suspicious)}"
        action = "flagged"

    if event_type is None:
        return None
    return {
        "eventType": event_type,
        "ip": ip or "0.0.0.0",
        "method": method,
        "path": path,
        "userAgent": user_agent,
        "statusCode": status_code,
        "severity": severity,
        "clMode": "external",
        "authPhase": "post_auth" if user_id else "pre_auth",
        "actionTaken": action,
        "responseLatencyMs": latency_ms,
        "userId": user_id,
        "metadata": {"reason": reason},
    }
