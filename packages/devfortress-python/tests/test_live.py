"""Live checks against the local platform (localhost:3001) and local Postgres."""

import secrets
import time
import uuid

import pytest
import requests

from conftest import local_db_url
from devfortress import DevFortressClient, DevFortressError

BASE = "http://localhost:3001"
INGEST = f"{BASE}/api/events/ingest"
DEV_EMAIL = "dev-admin@apiforge.local"

pytestmark = pytest.mark.live

psycopg2 = pytest.importorskip("psycopg2")


@pytest.fixture(scope="module")
def db():
    url = local_db_url()
    if not url:
        pytest.skip("no local Postgres URL (set DF_TEST_DATABASE_URL)")
    try:
        requests.get(f"{BASE}/api/health", timeout=90)
    except requests.RequestException:
        pytest.skip("local platform not running on :3001")
    conn = psycopg2.connect(url.split("?")[0])
    conn.autocommit = True
    yield conn
    conn.close()


@pytest.fixture(scope="module")
def project(db):
    """A dev project with its own surveillance key, removed afterwards."""
    cur = db.cursor()
    cur.execute('SELECT id FROM "User" WHERE email = %s', (DEV_EMAIL,))
    row = cur.fetchone()
    if not row:
        # dev login creates the user on first call
        requests.post(f"{BASE}/api/auth/dev", json={"role": "OWNER"}, timeout=60)
        cur.execute('SELECT id FROM "User" WHERE email = %s', (DEV_EMAIL,))
        row = cur.fetchone()
    if not row:
        pytest.skip("dev user unavailable")
    pid = "py" + uuid.uuid4().hex[:22]
    key = "vx_live_pytest_" + secrets.token_hex(12)
    cur.execute(
        'INSERT INTO "ApiProject" (id, name, slug, "createdById", "surveillanceApiKey", "updatedAt") '
        "VALUES (%s, %s, %s, %s, %s, now())",
        (pid, "pytest python sdk", "pytest-python-sdk-" + pid, row[0], key),
    )
    yield {"id": pid, "key": key}
    cur.execute('DELETE FROM "LiveThreatEvent" WHERE "projectId" = %s', (pid,))
    cur.execute('DELETE FROM "ApiProject" WHERE id = %s', (pid,))


def count_events(db, pid, marker):
    cur = db.cursor()
    cur.execute(
        'SELECT count(*) FROM "LiveThreatEvent" WHERE "projectId" = %s AND "requestPath" = %s',
        (pid, marker),
    )
    return cur.fetchone()[0]


def wait_count(db, pid, marker, expected, timeout=30):
    end = time.time() + timeout
    n = 0
    while time.time() < end:
        n = count_events(db, pid, marker)
        if n >= expected:
            return n
        time.sleep(0.5)
    return n


def event(path, i=0):
    return {
        "eventType": "custom",
        "ip": f"198.51.100.{10 + i}",
        "method": "GET",
        "path": path,
        "severity": "LOW",
        "authPhase": "pre_auth",
        "actionTaken": "monitored",
        "clMode": "external",
        "responseLatencyMs": 1,
        "userId": f"pytest-user-{i}",
    }


def test_single_event_is_accepted_and_stored(db, project):
    c = DevFortressClient(project["key"], endpoint=INGEST, timeout=90)
    marker = "/pytest/single/" + uuid.uuid4().hex[:8]
    res = c.track_event(event(marker))
    assert res["success"] is True and res["eventId"]
    assert wait_count(db, project["id"], marker, 1) == 1


def test_batch_events_are_accepted_and_stored(db, project):
    c = DevFortressClient(project["key"], endpoint=INGEST, timeout=90)
    marker = "/pytest/batch/" + uuid.uuid4().hex[:8]
    res = c.track_events([event(marker, i) for i in range(5)])
    assert res["success"] is True and res["successful"] == 5
    assert wait_count(db, project["id"], marker, 5) == 5


def test_queued_batching_delivers_25(db, project):
    c = DevFortressClient(project["key"], endpoint=INGEST, timeout=90, flush_interval=60)
    c.enable_batching()
    marker = "/pytest/queued/" + uuid.uuid4().hex[:8]
    for i in range(25):
        c.queue_event(event(marker, i))
    assert wait_count(db, project["id"], marker, 25) == 25
    c.close()


def test_test_connection_true_with_good_key(project):
    assert DevFortressClient(project["key"], endpoint=INGEST, timeout=90).test_connection() is True


def test_bad_key_gets_401_and_stores_nothing(db, project):
    c = DevFortressClient("vx_live_not_a_real_key", endpoint=INGEST, timeout=90, backoff_base=0.01)
    marker = "/pytest/badkey/" + uuid.uuid4().hex[:8]
    with pytest.raises(DevFortressError) as ei:
        c.track_event(event(marker))
    assert ei.value.status_code == 401
    assert count_events(db, project["id"], marker) == 0
    assert c.test_connection() is False
