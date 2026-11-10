"""Flask integration: ``DevFortressFlask(app, client=client)``."""

from __future__ import annotations

import asyncio
import json
import threading
import time
from typing import Callable, Iterable, Optional

from .classify import build_event
from .client import DevFortressClient
from .internal_closed_loop_engine import InternalCLRequest


class DevFortressFlask:
    def __init__(
        self,
        app=None,
        client: Optional[DevFortressClient] = None,
        *,
        api_key: Optional[str] = None,
        endpoint: Optional[str] = None,
        exclude_paths: Iterable[str] = ("/health",),
        on_error: Optional[Callable[[Exception], None]] = None,
    ):
        if client is None:
            if not api_key:
                raise ValueError("DevFortressFlask needs a client or an api_key")
            kwargs = {"endpoint": endpoint} if endpoint else {}
            client = DevFortressClient(api_key, on_error=on_error, **kwargs)
        self.client = client
        self.exclude_paths = tuple(exclude_paths)
        self.on_error = on_error
        if app is not None:
            self.init_app(app)

    def init_app(self, app) -> None:
        from flask import g, request, Response

        @app.before_request
        def _df_start():
            g._df_started = time.monotonic()

            if self.client.mode in ("internal", "hybrid") and not request.path.startswith(self.exclude_paths):
                ip = (
                    request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                    or request.headers.get("X-Real-IP", "")
                    or request.remote_addr
                    or "0.0.0.0"
                )
                # Flask buffers the body eagerly, so (unlike the ASGI/FastAPI
                # gate) the body can be included in the Tier-1 match here
                # without affecting the downstream view's own body read.
                body = request.get_data(as_text=True, parse_form_data=False) or None
                req = InternalCLRequest(
                    ip=ip,
                    method=request.method,
                    path=request.path,
                    user_agent=request.headers.get("User-Agent"),
                    query=request.query_string.decode("latin-1"),
                    headers=dict(request.headers),
                    body=body,
                )
                result = asyncio.run(self.client.observe(req))
                if result and result.get("flagged"):
                    return Response(
                        response=json.dumps(
                            {"error": "blocked", "reason": result.get("decision"), "eventId": result.get("event_id")}
                        ),
                        status=403,
                        mimetype="application/json",
                    )
            return None

        @app.after_request
        def _df_after(response):
            if request.path.startswith(self.exclude_paths):
                return response
            started = getattr(g, "_df_started", time.monotonic())
            ip = (
                request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                or request.headers.get("X-Real-IP", "")
                or request.remote_addr
                or "0.0.0.0"
            )
            event = build_event(
                ip=ip,
                method=request.method,
                path=request.path,
                status_code=response.status_code,
                latency_ms=round((time.monotonic() - started) * 1000),
                user_agent=request.headers.get("User-Agent"),
                query=request.query_string.decode("latin-1"),
            )
            if event is not None:
                threading.Thread(target=self._send, args=(event,), daemon=True).start()
            return response

    def _send(self, event) -> None:
        try:
            self.client.track_event(event)
        except Exception as exc:
            if self.on_error:
                self.on_error(exc)
