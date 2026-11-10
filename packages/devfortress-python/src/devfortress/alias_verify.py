"""Alias binding verification helper.

Port of the Node SDK's ``alias-verify.ts``. Thin HTTP transport for
``POST /api/aliases/{id}/verify``. All binding checks run server-side;
nothing is evaluated locally. Retry behaviour matches ``DevFortressClient``:
exponential backoff on 5xx and network errors only, never on 4xx.

Runs the blocking ``requests`` call in a worker thread via
``asyncio.to_thread`` so the async surface doesn't block the event loop,
without pulling in a second HTTP library.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import quote

import requests

from .version import SDK_VERSION

DEFAULT_BASE_URL = "https://www.devfortress.net"
DEFAULT_TIMEOUT = 15.0
DEFAULT_RETRIES = 3

AliasOperationClass = Literal["read", "download", "list", "write", "publish", "message"]


@dataclass
class AliasVerifyContext:
    request_ip: str
    geo_country: Optional[str] = None
    workload_id: Optional[str] = None
    device_fingerprint: Optional[str] = None
    app_bundle_id: Optional[str] = None
    agent_tool_id: Optional[str] = None
    request_timestamp: Optional[str] = None  # ISO-8601
    container_id: Optional[str] = None
    egress_path: Optional[str] = None
    process_signature: Optional[str] = None
    observed_operation_class: Optional[AliasOperationClass] = None
    observed_model_identifier: Optional[str] = None

    def to_wire(self) -> Dict[str, Any]:
        return {
            "requestIp": self.request_ip,
            "geoCountry": self.geo_country,
            "workloadId": self.workload_id,
            "deviceFingerprint": self.device_fingerprint,
            "appBundleId": self.app_bundle_id,
            "agentToolId": self.agent_tool_id,
            "requestTimestamp": self.request_timestamp,
            "containerId": self.container_id,
            "egressPath": self.egress_path,
            "processSignature": self.process_signature,
            "observedOperationClass": self.observed_operation_class,
            "observedModelIdentifier": self.observed_model_identifier,
        }


@dataclass
class AliasBindingViolation:
    type: str
    alias_id: str
    severity: str
    response: str
    expected: Any = None
    received: Any = None


@dataclass
class AliasVerifyResult:
    http_status: int
    valid: bool
    violations: List[AliasBindingViolation] = field(default_factory=list)
    note: Optional[str] = None
    code: Optional[str] = None
    state: Optional[str] = None
    error: Optional[str] = None


class AliasVerifyError(Exception):
    def __init__(self, message: str, http_status: Optional[int] = None, body: Any = None):
        super().__init__(message)
        self.http_status = http_status
        self.body = body


def _verify_sync(
    alias_id: str,
    alias_key: str,
    context: AliasVerifyContext,
    base_url: str,
    timeout: float,
    retries: int,
) -> Dict[str, Any]:
    url = f"{base_url.rstrip('/')}/api/aliases/{quote(alias_id, safe='')}/verify"

    attempt = 1
    while True:
        try:
            response = requests.post(
                url,
                json={"aliasKey": alias_key, "context": context.to_wire()},
                timeout=timeout,
                headers={
                    "Content-Type": "application/json",
                    "X-DevFortress-SDK-Version": SDK_VERSION,
                },
            )
            status = response.status_code
            try:
                data = response.json()
            except ValueError:
                data = {}

            if status in (200, 403):
                return {"httpStatus": status, "violations": [], **data}
            if status < 500:
                raise AliasVerifyError(
                    data.get("error") or f"Alias verification failed with status {status}", status, data
                )
            if attempt >= retries:
                raise AliasVerifyError(
                    data.get("error") or f"Alias verification failed with status {status}", status, data
                )
        except AliasVerifyError as error:
            # Only 5xx reaches here with retries left; 4xx is final.
            if (error.http_status or 500) < 500 or attempt >= retries:
                raise
        except requests.RequestException as exc:
            if attempt >= retries:
                raise AliasVerifyError(f"Alias verification request failed: {exc}") from exc

        import time as _time

        _time.sleep(2 ** attempt)
        attempt += 1


async def verify_alias_binding(
    alias_id: str,
    alias_key: str,
    context: AliasVerifyContext,
    *,
    base_url: str = DEFAULT_BASE_URL,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
) -> AliasVerifyResult:
    """Verify an alias's observed context against its recorded binding.

    Resolves for 200 and 403 responses (the platform's normal verdicts).
    Raises AliasVerifyError for 400/401 and for 5xx/network failures once
    retries are exhausted.
    """
    if not alias_id:
        raise ValueError("verify_alias_binding: alias_id is required")
    if not alias_key:
        raise ValueError("verify_alias_binding: alias_key is required")

    data = await asyncio.to_thread(_verify_sync, alias_id, alias_key, context, base_url, timeout, retries)

    violations = [
        AliasBindingViolation(
            type=v.get("type", ""),
            alias_id=v.get("aliasId", alias_id),
            severity=v.get("severity", ""),
            response=v.get("response", ""),
            expected=v.get("expected"),
            received=v.get("received"),
        )
        for v in data.get("violations", [])
    ]

    return AliasVerifyResult(
        http_status=data["httpStatus"],
        valid=data.get("valid", False),
        violations=violations,
        note=data.get("note"),
        code=data.get("code"),
        state=data.get("state"),
        error=data.get("error"),
    )
