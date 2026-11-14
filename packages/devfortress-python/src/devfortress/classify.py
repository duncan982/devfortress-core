"""Maps an HTTP response to a DevFortress event, as the Node middleware does."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import unquote_plus

try:
    import bleach
    HAS_BLEACH = True
except ImportError:
    # devfortress-python declares bleach as a hard dependency (pyproject.toml),
    # but this module is also imported via a bare PYTHONPATH (no pip install)
    # in e2e harnesses that only guarantee the stdlib plus whatever's already
    # on the system interpreter — same reasoning as the HAS_FLASK/HAS_BLEACH
    # pattern in middleware/flask.py and middleware/fastapi.py.
    HAS_BLEACH = False

_SQL = [
    re.compile(r"(\bor\b.*=.*)", re.I),
    re.compile(r"(\bunion\b.*\bselect\b)", re.I),
    re.compile(r"(\bdrop\b.*\btable\b)", re.I),
    re.compile(r"('\s*or\s*'1'\s*=\s*'1)", re.I),
]
_XSS = [
    re.compile(r"javascript:", re.I),
    re.compile(r"onerror\s*=\s*", re.I),
    re.compile(r"onload\s*=\s*", re.I),
]
_TRAVERSAL = [re.compile(r"\.\.[/\\]"), re.compile(r"/etc/passwd", re.I)]


def _has_script_tag(text: str) -> bool:
    """True if `text` contains a <script> tag.

    Primary check is a plain linear scan for "<script" eventually
    followed by "</script>" — same reach as the
    ``<script[^>]*>[\\s\\S]*?</script>`` regex this replaces (including
    the classic ``<scr<script>ipt>`` nesting trick), but with no
    backtracking. Malformed markup that survives the scan (a "<script"
    with no matching close) is confirmed via bleach's real HTML parser
    actually stripping something — not just the literal substring
    appearing in plain prose."""
    lower = text.lower()
    open_idx = lower.find("<script")
    if open_idx != -1 and lower.find("</script>", open_idx) != -1:
        return True
    if "<script" not in lower:
        return False
    if not HAS_BLEACH:
        return True
    return bleach.clean(text, tags=[], strip=True) != text


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
    if hit(_XSS) or any(_has_script_tag(c) for c in candidates):
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
