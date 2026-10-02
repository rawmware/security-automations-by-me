"""Hermetic tests for the web layer: DB + FastAPI routes."""

import textwrap

import pytest
from fastapi.testclient import TestClient

from sentinel.findings import Finding, Severity
from sentinel.web.app import create_app
from sentinel.web.db import DB

MIN_CONFIG = textwrap.dedent("""\
    version: 1
    state_dir: {state}
    reports_dir: {reports}
    interval_minutes: 60
    notifications:
      stdout:
        enabled: false
    automations: {{}}
    """)


@pytest.fixture()
def app_client(tmp_path):
    cfg = tmp_path / "automations.yaml"
    cfg.write_text(MIN_CONFIG.format(state=tmp_path / "state",
                                     reports=tmp_path / "reports"))
    with TestClient(create_app(str(cfg))) as client:
        yield client


def test_db_roundtrip(tmp_path):
    db = DB(tmp_path / "t.db")
    f = Finding(automation="tls_watch", title="t", severity=Severity.HIGH,
                description="d", evidence={"a": 1}, recommendation="r")
    db.save_run_started("abc123")
    db.save_run_finished("abc123", [f])
    stats = db.stats()
    assert stats["total_findings"] == 1
    assert stats["by_severity"]["HIGH"] == 1
    rows = db.list_findings()
    assert rows[0]["title"] == "t" and rows[0]["run_id"] == "abc123"
    assert db.get_finding(rows[0]["id"])["title"] == "t"
    runs = db.list_runs()
    assert runs[0]["status"] == "done" and runs[0]["findings_total"] == 1


def test_dashboard_renders(app_client):
    r = app_client.get("/")
    assert r.status_code == 200
    assert "SENTINEL" in r.text


def test_api_stats(app_client):
    r = app_client.get("/api/stats")
    assert r.status_code == 200
    assert r.json()["total_findings"] == 0


def test_pages_render(app_client):
    for path in ["/findings", "/automations", "/runs", "/reports", "/settings",
                 "/automations/typo_watch"]:
        r = app_client.get(path)
        assert r.status_code == 200, path


def test_unknown_automation_404(app_client):
    assert app_client.get("/automations/nope").status_code == 404


def test_toggle_roundtrip(app_client):
    r = app_client.post("/automations/typo_watch/toggle",
                        data={"enabled": "on"}, follow_redirects=False)
    assert r.status_code == 303
    r = app_client.get("/automations/typo_watch")
    assert "Enabled" in r.text
