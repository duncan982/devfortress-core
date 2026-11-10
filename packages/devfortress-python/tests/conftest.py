import json
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
VECTOR_FILE = REPO_ROOT / "contracts" / "webhook-signature-vectors.json"
INGEST_VECTOR_FILE = REPO_ROOT / "contracts" / "ingest-signature-vectors.json"


class StubServer:
    """Scripted HTTP server. `responses` is consumed in order; the last one repeats."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length)
                stub.requests.append(
                    {
                        "headers": dict(self.headers),
                        "body": json.loads(raw or b"{}"),
                        "raw": raw,
                        "method": self.command,
                        "path": self.path,
                    }
                )
                idx = min(len(stub.requests) - 1, len(stub.responses) - 1)
                status, payload = stub.responses[idx]
                out = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *args):
                pass

        self._httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._httpd.server_port}/api/events/ingest"
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()

    def close(self):
        self._httpd.shutdown()
        self._httpd.server_close()


@pytest.fixture
def stub_server():
    servers = []

    def make(responses):
        s = StubServer(responses)
        servers.append(s)
        return s

    yield make
    for s in servers:
        s.close()


@pytest.fixture(scope="session")
def vectors():
    return json.loads(VECTOR_FILE.read_text(encoding="utf-8"))["vectors"]


def local_db_url():
    """Local Postgres only. Never falls back to a remote URL."""
    url = os.environ.get("DF_TEST_DATABASE_URL")
    if url:
        return url
    env = REPO_ROOT / ".env.local"
    if env.exists():
        for line in env.read_text().splitlines():
            m = re.match(r"^DIRECT_DATABASE_URL=(\S+)", line)
            if m and "127.0.0.1" in m.group(1):
                return m.group(1)
    return None


@pytest.fixture(scope="session")
def ingest_vector_file():
    return json.loads(INGEST_VECTOR_FILE.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def ingest_vectors():
    return json.loads(INGEST_VECTOR_FILE.read_text(encoding="utf-8"))["vectors"]
