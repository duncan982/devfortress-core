"""ASGI middleware for FastAPI / Starlette. No framework import needed."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Callable, Iterable, Optional

from .classify import build_event
from .client import DevFortressClient
from .internal_closed_loop_engine import InternalCLRequest


class DevFortressMiddleware:
    """``app.add_middleware(DevFortressMiddleware, client=client)``"""

    def __init__(
        self,
        app,
        client: Optional[DevFortressClient] = None,
        *,
        api_key: Optional[str] = None,
        endpoint: Optional[str] = None,
        exclude_paths: Iterable[str] = ("/health", "/docs", "/openapi.json"),
        on_error: Optional[Callable[[Exception], None]] = None,
    ):
        if client is None:
            if not api_key:
                raise ValueError("DevFortressMiddleware needs a client or an api_key")
            kwargs = {"endpoint": endpoint} if endpoint else {}
            client = DevFortressClient(api_key, on_error=on_error, **kwargs)
        self.app = app
        self.client = client
        self.exclude_paths = tuple(exclude_paths)
        self.on_error = on_error
        self._tasks: set = set()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"].startswith(self.exclude_paths):
            await self.app(scope, receive, send)
            return

        if self.client.mode in ("internal", "hybrid"):
            blocked = await self._internal_gate(scope, send)
            if blocked:
                return

        started = time.monotonic()
        status = {"code": 500}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status["code"] = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            self._emit(scope, status["code"], started)

    def _emit(self, scope, status_code: int, started: float) -> None:
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        ip = (
            headers.get("x-forwarded-for", "").split(",")[0].strip()
            or headers.get("x-real-ip", "")
            or (scope["client"][0] if scope.get("client") else "0.0.0.0")
        )
        event = build_event(
            ip=ip,
            method=scope["method"],
            path=scope["path"],
            status_code=status_code,
            latency_ms=round((time.monotonic() - started) * 1000),
            user_agent=headers.get("user-agent"),
            query=scope.get("query_string", b"").decode("latin-1"),
        )
        if event is None:
            return
        task = asyncio.ensure_future(self._send(event))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _send(self, event) -> None:
        try:
            await asyncio.get_running_loop().run_in_executor(None, self.client.track_event, event)
        except Exception as exc:
            if self.on_error:
                self.on_error(exc)

    async def _internal_gate(self, scope, send) -> bool:
        """Pre-response internal/hybrid-mode gate. Returns True if the
        request was blocked (caller must not forward to the app).

        Scope: inspects path, query string, and headers only — not the
        request body. Re-reading the ASGI body stream here without also
        replaying it to the downstream app would break every route that
        reads its own body, so body-based Tier-1 rules (SQLi/XSS patterns
        matched against the request body) do not fire on this path. This
        is a known, documented scope limitation, not silently claimed as
        full parity with Node's body-inspecting variant.
        """
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        ip = (
            headers.get("x-forwarded-for", "").split(",")[0].strip()
            or headers.get("x-real-ip", "")
            or (scope["client"][0] if scope.get("client") else "0.0.0.0")
        )
        req = InternalCLRequest(
            ip=ip,
            method=scope["method"],
            path=scope["path"],
            user_agent=headers.get("user-agent"),
            query=scope.get("query_string", b"").decode("latin-1"),
            headers=headers,
        )
        result = await self.client.observe(req)
        if result and result.get("flagged"):
            body = json.dumps(
                {"error": "blocked", "reason": result.get("decision"), "eventId": result.get("event_id")}
            ).encode("utf-8")
            await send(
                {
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [[b"content-type", b"application/json"]],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return True
        return False
