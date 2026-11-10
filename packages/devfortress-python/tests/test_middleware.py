import time

from devfortress import DevFortressClient, DevFortressMiddleware, DevFortressFlask
from devfortress import init, get_instance


def wait_for(stub, n, timeout=5):
    end = time.time() + timeout
    while len(stub.requests) < n and time.time() < end:
        time.sleep(0.05)


def test_fastapi_reports_auth_failure_and_skips_ok(stub_server):
    from fastapi import FastAPI, HTTPException
    from fastapi.testclient import TestClient

    s = stub_server([(200, {"success": True})])
    client = DevFortressClient("vx_live_x", endpoint=s.url, backoff_base=0.01)
    app = FastAPI()
    app.add_middleware(DevFortressMiddleware, client=client)

    @app.get("/ok")
    def ok():
        return {"ok": True}

    @app.get("/secret")
    def secret():
        raise HTTPException(status_code=401)

    tc = TestClient(app)
    assert tc.get("/ok").status_code == 200
    assert tc.get("/secret").status_code == 401
    wait_for(s, 1)
    assert len(s.requests) == 1
    body = s.requests[0]["body"]
    assert body["eventType"] == "auth_failure" and body["path"] == "/secret"
    assert body["clMode"] == "external" and body["actionTaken"] == "blocked"


def test_fastapi_flags_suspicious_path(stub_server):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    s = stub_server([(200, {"success": True})])
    app = FastAPI()
    app.add_middleware(
        DevFortressMiddleware, client=DevFortressClient("vx_live_x", endpoint=s.url)
    )
    TestClient(app).get("/files/../../etc/passwd")
    wait_for(s, 1)
    assert s.requests[0]["body"]["eventType"] == "suspicious_pattern"


def test_flask_reports_5xx(stub_server):
    from flask import Flask

    s = stub_server([(200, {"success": True})])
    app = Flask(__name__)
    DevFortressFlask(app, client=DevFortressClient("vx_live_x", endpoint=s.url))

    @app.route("/boom")
    def boom():
        return "no", 500

    @app.route("/fine")
    def fine():
        return "yes"

    c = app.test_client()
    assert c.get("/fine").status_code == 200
    assert c.get("/boom").status_code == 500
    wait_for(s, 1)
    assert len(s.requests) == 1
    assert s.requests[0]["body"]["eventType"] == "5xx_error"


def test_quick_init_sets_defaults(stub_server):
    s = stub_server([(200, {"success": True})])
    c = init("vx_live_x", app_id="my-app", endpoint=s.url, environment="test")
    assert get_instance() is c
    c.track_event({"eventType": "custom", "ip": "1.2.3.4", "method": "GET", "path": "/", "severity": "LOW"})
    body = s.requests[0]["body"]
    assert body["appId"] == "my-app" and body["environment"] == "test"
