"""
DevFortress FastAPI Middleware

Automatically monitors FastAPI applications for security events and sends
them to the DevFortress surveillance API.

Usage:
    from devfortress_middleware import DevFortressMiddleware

    app = FastAPI()
    app.add_middleware(
        DevFortressMiddleware,
        api_key="your-api-key",
        endpoint="https://www.devfortress.net/api/events/ingest"
    )
"""

import time
import re
import json
import asyncio
from typing import Optional, List, Dict, Any, Callable
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

try:
    from urllib.request import Request as URLRequest, urlopen
    from urllib.error import URLError
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False

try:
    import bleach
    HAS_BLEACH = True
except ImportError:
    HAS_BLEACH = False


# SQL Injection patterns
SQL_PATTERNS = [
    re.compile(r"(\bor\b.*=.*)", re.IGNORECASE),
    re.compile(r"(\bunion\b.*\bselect\b)", re.IGNORECASE),
    re.compile(r"(\bdrop\b.*\btable\b)", re.IGNORECASE),
    re.compile(r"('\s*or\s*'1'\s*=\s*'1)", re.IGNORECASE),
]

# XSS patterns
XSS_PATTERNS = [
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"onerror\s*=\s*", re.IGNORECASE),
    re.compile(r"onload\s*=\s*", re.IGNORECASE),
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
    matching HAS_HTTPX/HAS_URLLIB above)."""
    lower = text.lower()
    open_idx = lower.find("<script")
    if open_idx != -1 and lower.find("</script>", open_idx) != -1:
        return True
    if "<script" not in lower:
        return False
    if not HAS_BLEACH:
        return True
    return bleach.clean(text, tags=[], strip=True) != text

# Path traversal patterns
TRAVERSAL_PATTERNS = [
    re.compile(r"\.\.[/\\]"),
    re.compile(r"/etc/passwd", re.IGNORECASE),
]


class DevFortressMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware for DevFortress security monitoring."""

    def __init__(
        self,
        app,
        api_key: str,
        endpoint: str = "https://www.devfortress.net/api/events/ingest",
        exclude_paths: Optional[List[str]] = None,
        capture_headers: bool = False,
        debug: bool = False,
        on_error: Optional[Callable[[Exception], None]] = None,
    ):
        super().__init__(app)
        self.api_key = api_key
        self.endpoint = endpoint
        self.exclude_paths = exclude_paths or ["/health", "/docs", "/openapi.json"]
        self.capture_headers = capture_headers
        self.debug = debug
        self.on_error = on_error

    async def dispatch(self, request: Request, call_next) -> Response:
        # Skip excluded paths
        if any(request.url.path.startswith(p) for p in self.exclude_paths):
            return await call_next(request)

        start_time = time.time()
        response: Optional[Response] = None

        try:
            response = await call_next(request)
        except Exception as exc:
            # Track server error
            await self._track_event(
                request=request,
                status_code=500,
                response_time=time.time() - start_time,
                event_type="5xx_error",
                severity="HIGH",
                reason=f"Unhandled exception: {str(exc)}",
            )
            raise

        response_time = time.time() - start_time
        status_code = response.status_code

        # Determine event type
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

        # Check suspicious patterns
        suspicious = self._detect_suspicious(request)
        if suspicious:
            event_type = "suspicious_pattern"
            severity = "HIGH"
            reason = f"Suspicious patterns: {', '.join(suspicious)}"

        if event_type:
            # Fire and forget
            asyncio.create_task(
                self._track_event(
                    request=request,
                    status_code=status_code,
                    response_time=response_time,
                    event_type=event_type,
                    severity=severity,
                    reason=reason,
                )
            )

        return response

    async def _track_event(
        self,
        request: Request,
        status_code: int,
        response_time: float,
        event_type: str,
        severity: str,
        reason: Optional[str] = None,
    ):
        """Send event to DevFortress API."""
        ip = (
            request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            or request.headers.get("x-real-ip", "")
            or (request.client.host if request.client else "0.0.0.0")
        )

        payload: Dict[str, Any] = {
            "eventType": event_type,
            "ip": ip,
            "method": request.method,
            "path": str(request.url.path),
            "userAgent": request.headers.get("user-agent"),
            "statusCode": status_code,
            "responseTime": round(response_time * 1000),
            "severity": severity,
            "reason": reason,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        if self.capture_headers:
            payload["metadata"] = {"headers": dict(request.headers)}

        try:
            if HAS_HTTPX:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    await client.post(
                        self.endpoint,
                        json=payload,
                        headers={
                            "Content-Type": "application/json",
                            "X-DevFortress-Key": self.api_key,
                        },
                    )
            elif HAS_URLLIB:
                req = URLRequest(
                    self.endpoint,
                    data=json.dumps(payload).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "X-DevFortress-Key": self.api_key,
                    },
                    method="POST",
                )
                urlopen(req, timeout=5)
        except Exception as exc:
            if self.on_error:
                self.on_error(exc)
            elif self.debug:
                print(f"[DevFortress] Failed to send event: {exc}")  # noqa: T201

    def _detect_suspicious(self, request: Request) -> List[str]:
        """Detect suspicious patterns in the request."""
        patterns_found = []
        url_str = str(request.url)
        query_str = str(request.query_params)
        check_str = f"{url_str} {query_str}"

        if any(p.search(check_str) for p in SQL_PATTERNS):
            patterns_found.append("sql_injection")
        if _has_script_tag(check_str) or any(p.search(check_str) for p in XSS_PATTERNS):
            patterns_found.append("xss")
        if any(p.search(check_str) for p in TRAVERSAL_PATTERNS):
            patterns_found.append("path_traversal")

        return patterns_found
