"""Shared cross-language vectors: the Node SDK's own test suite asserts the same file."""

import json
import shutil
import subprocess

import pytest

from conftest import REPO_ROOT
from devfortress import verify_webhook_signature


def test_vectors_present(vectors):
    assert len(vectors) >= 10


def test_python_matches_expected(vectors):
    for v in vectors:
        result = verify_webhook_signature(
            v["body"], v["signature"], v["timestamp"], v["secret"], now=v["now"]
        )
        assert result.valid is v["expected_valid"], f'{v["name"]}: {result.reason}'


def test_nonce_replay_is_detected():
    import hashlib
    import hmac

    body = json.dumps({"nonce": "a1b2c3d4e5f60718293a4b5c6d7e8f90"})
    ts = "2026-01-15T12:00:00.000Z"
    sig = hmac.new(b"s", f"{ts}.{body}".encode(), hashlib.sha256).hexdigest()
    seen = set()

    def check(n):
        if n in seen:
            return False
        seen.add(n)
        return True

    kw = dict(now=ts, nonce_check=check)
    assert verify_webhook_signature(body, sig, ts, "s", **kw).valid
    second = verify_webhook_signature(body, sig, ts, "s", **kw)
    assert not second.valid and second.reason == "replay_detected"


@pytest.mark.skipif(shutil.which("npx") is None, reason="npx not available")
def test_node_sdk_agrees_on_every_vector(vectors):
    """Run the Node SDK's own vector test and require every vector to pass there too."""
    sdk = REPO_ROOT / "packages" / "devfortress-sdk"
    proc = subprocess.run(
        ["npx", "jest", "__tests__/webhook-signature-vectors.test.ts", "--json", "--silent"],
        cwd=sdk,
        capture_output=True,
        text=True,
        timeout=600,
    )
    report = json.loads(proc.stdout[proc.stdout.index("{"):])
    node_results = {
        t["title"]: t["status"] for s in report["testResults"] for t in s["assertionResults"]
    }
    for v in vectors:
        assert node_results.get(v["name"]) == "passed", f'Node disagrees on {v["name"]}'
    # Same expectations on both sides, so identical verdicts follow.
    for v in vectors:
        py = verify_webhook_signature(
            v["body"], v["signature"], v["timestamp"], v["secret"], now=v["now"]
        ).valid
        assert py is v["expected_valid"]
