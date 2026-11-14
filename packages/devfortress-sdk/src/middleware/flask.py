"""
DevFortress Flask Middleware

Automatically monitors Flask applications for security events and sends
them to the DevFortress surveillance API.

Usage:
    from devfortress_middleware import DevFortressFlask

    app = Flask(__name__)
    devfortress = DevFortressFlask(
        app,
        api_key="your-api-key",
        endpoint="https://www.devfortress.net/api/events/ingest"
    )
"""

import time
import re
import json
import threading
from typing import Optional, List, Dict, Any, Callable

try:
    from flask import Flask, request, g
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

try:
    import bleach
    HAS_BLEACH = True
except ImportError:
    HAS_BLEACH = False

try:
    import requests as http_requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from urllib.request import Request as URLRequest, urlopen
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False


# Detection patterns
SQL_PATTERNS = [
    re.compile(r"(\bor\b.*=.*)", re.IGNORECASE),
    re.compile(r"(\bunion\b.*\bselect\b)", re.IGNORECASE),
    re.compile(r"(\bdrop\b.*\btable\b)", re.IGNORECASE),
    re.compile(r"('\s*or\s*'1'\s*=\s*'1)", re.IGNORECASE),
]

XSS_PATTERNS = [
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"onerror\s*=\s*", re.IGNORECASE),
]


def _has_script_tag(text: str) -> bool:
    """True if `text` contains a <script> tag.

    Primary check is a plain linear scan for "<script" eventually
    followed by "</script>" — same reach as the
    ``<script[^>]*>[\\s\\S]*?</script>`` regex this replaces (including
    the classic ``<scr<script>ipt>`` nesting trick), but with no
    backtracking. When bleach is installed, malformed markup that
    survives the scan (a "<script" with no matching close) is confirmed
    by checking that bleach's real HTML parser actually stripped
    something — not just the literal substring in plain prose. Falls
    back to the scan alone when bleach isn't installed (this file has
    no packaging manifest of its own to declare it as a hard dependency,
    matching HAS_FLASK/HAS_REQUESTS above)."""
    lower = text.lower()
    open_idx = lower.find("<script")
    if open_idx != -1 and lower.find("</script>", open_idx) != -1:
        return True
    if "<script" not in lower:
        return False
    if not HAS_BLEACH:
        return True
    return bleach.clean(text, tags=[], strip=True) != text

TRAVERSAL_PATTERNS = [
    re.compile(r"\.\.[/\\]"),
    re.compile(r"/etc/passwd", re.IGNORECASE),
]


class DevFortressFlask:
    """Flask extension for DevFortress security monitoring."""

    def __init__(
        self,
        app: Optional["Flask"] = None,
        api_key: str = "",
        endpoint: str = "https://www.devfortress.net/api/events/ingest",
        exclude_paths: Optional[List[str]] = None,
        capture_headers: bool = False,
        debug: bool = False,
        on_error: Optional[Callable[[Exception], None]] = None,
    ):
        self.api_key = api_key
        self.endpoint = endpoint
        self.exclude_paths = exclude_paths or ["/health", "/static"]
        self.capture_headers = capture_headers
        self.debug = debug
        self.on_error = on_error

        if app is not None:
            self.init_app(app)

    def init_app(self, app: "Flask"):
        """Initialize Flask app with DevFortress monitoring."""
        if not HAS_FLASK:
            raise ImportError("Flask is required for DevFortressFlask middleware")

        app.before_request(self._before_request)
        app.after_request(self._after_request)

    def _before_request(self):
        """Record request start time."""
        g.devfortress_start_time = time.time()

    def _after_request(self, response):
        """Analyze response and track security events."""
        # Skip excluded paths
        if any(request.path.startswith(p) for p in self.exclude_paths):
            return response

        start_time = getattr(g, "devfortress_start_time", time.time())
        response_time = time.time() - start_time
        status_code = response.status_code

        event_type = None
        severity = "LOW"
        reason = None

        if status_code in (401, 403):
            event_type = "auth_failure"
            severity = "MEDIUM"
            reason = "Authentication or authorization failed"
        elif status_code in (400, 422):
            event_type = "validation_error"
            severity = "LOW"
            reason = "Request validation failed"
        elif status_code == 429:
            event_type = "rate_limit_exceeded"
            severity = "MEDIUM"
            reason = "Rate limit exceeded"
        elif status_code >= 500:
            event_type = "5xx_error"
            severity = "HIGH"
            reason = f"Server error: {status_code}"
        elif status_code >= 400:
            event_type = "4xx_error"
            severity = "LOW"
            reason = f"Client error: {status_code}"

        # Suspicious pattern detection
        suspicious = self._detect_suspicious()
        if suspicious:
            event_type = "suspicious_pattern"
            severity = "HIGH"
            reason = f"Suspicious patterns: {', '.join(suspicious)}"

        if event_type:
            ip = (
                request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                or request.headers.get("X-Real-IP", "")
                or request.remote_addr
                or "0.0.0.0"
            )

            payload: Dict[str, Any] = {
                "eventType": event_type,
                "ip": ip,
                "method": request.method,
                "path": request.path,
                "userAgent": request.user_agent.string if request.user_agent else None,
                "statusCode": status_code,
                "responseTime": round(response_time * 1000),
                "severity": severity,
                "reason": reason,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }

            if self.capture_headers:
                payload["metadata"] = {"headers": dict(request.headers)}

            # Send asynchronously to avoid blocking the response
            thread = threading.Thread(
                target=self._send_event, args=(payload,), daemon=True
            )
            thread.start()

        return response

    def _send_event(self, payload: Dict[str, Any]):
        """Send event to DevFortress API (runs in background thread)."""
        headers = {
            "Content-Type": "application/json",
            "X-DevFortress-Key": self.api_key,
        }

        try:
            if HAS_REQUESTS:
                http_requests.post(
                    self.endpoint,
                    json=payload,
                    headers=headers,
                    timeout=5,
                )
            elif HAS_URLLIB:
                req = URLRequest(
                    self.endpoint,
                    data=json.dumps(payload).encode("utf-8"),
                    headers=headers,
                    method="POST",
                )
                urlopen(req, timeout=5)
        except Exception as exc:
            if self.on_error:
                self.on_error(exc)
            elif self.debug:
                print(f"[DevFortress] Failed to send event: {exc}")  # noqa: T201

    def _detect_suspicious(self) -> List[str]:
        """Detect suspicious patterns in the request."""
        patterns_found = []
        check_str = f"{request.url} {request.query_string.decode('utf-8', errors='ignore')}"

        if any(p.search(check_str) for p in SQL_PATTERNS):
            patterns_found.append("sql_injection")
        if _has_script_tag(check_str) or any(p.search(check_str) for p in XSS_PATTERNS):
            patterns_found.append("xss")
        if any(p.search(check_str) for p in TRAVERSAL_PATTERNS):
            patterns_found.append("path_traversal")

        return patterns_found
