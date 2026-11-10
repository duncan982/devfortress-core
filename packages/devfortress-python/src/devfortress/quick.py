"""One-call setup, the counterpart of the Node SDK's ``quick.init``."""

from __future__ import annotations

import os
from typing import Optional

from .client import DevFortressClient

_instance: Optional[DevFortressClient] = None


def init(
    api_key: str,
    app_id: Optional[str] = None,
    privacy: str = "standard",
    debug: bool = False,
    endpoint: Optional[str] = None,
    environment: Optional[str] = None,
) -> DevFortressClient:
    global _instance
    defaults = {
        "appId": app_id or os.path.basename(os.getcwd()) or "app",
        "environment": environment or os.environ.get("APP_ENV", "production"),
    }
    kwargs = {"endpoint": endpoint} if endpoint else {}
    _instance = DevFortressClient(
        api_key, debug=debug, privacy=privacy, defaults=defaults, **kwargs
    )
    return _instance


def get_instance() -> Optional[DevFortressClient]:
    return _instance
