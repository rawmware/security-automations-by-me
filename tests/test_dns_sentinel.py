"""Hermetic tests for dns_sentinel (snapshot monkeypatched)."""

from sentinel import dns_sentinel
from sentinel.findings import Severity

SNAP_V1 = {"A": ["93.184.216.34"], "AAAA": [], "CNAME": [], "MX": ["10 mail.example.com"],
           "TXT": ["v=spf1 -all"], "NS": ["ns1.example.com"], "SOA": ["2024010101"]}
SNAP_V2 = dict(SNAP_V1, A=["93.184.216.99"])  # A record changed
SNAP_V3 = dict(SNAP_V1, NS=["ns-evil.example.net"])  # NS hijack


def test_diff_detects_added_removed():
    drift = dns_sentinel.diff_records(SNAP_V1, SNAP_V2)
    assert drift["A"] == {"added": ["93.184.216.99"], "removed": ["93.184.216.34"]}


def test_diff_clean_is_empty():
    assert dns_sentinel.diff_records(SNAP_V1, dict(SNAP_V1)) == {}


def test_ns_severity_is_high():
    assert dns_sentinel.SEVERITY_BY_TYPE["NS"] == Severity.HIGH
    assert dns_sentinel.SEVERITY_BY_TYPE["MX"] == Severity.HIGH


def _run_with(snaps, monkeypatch):
    it = iter(snaps)
    monkeypatch.setattr(dns_sentinel, "snapshot", lambda domain, timeout=5.0: next(it))
    return dns_sentinel.run({"domains": ["example.com"]}, {})


def test_first_run_establishes_baseline(monkeypatch):
    findings = _run_with([SNAP_V1], monkeypatch)
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "baseline" in findings[0].title.lower()


def test_a_drift_is_medium(monkeypatch):
    state = {}
    monkeypatch.setattr(dns_sentinel, "snapshot", lambda d, timeout=5.0: SNAP_V1)
    dns_sentinel.run({"domains": ["example.com"]}, state)
    monkeypatch.setattr(dns_sentinel, "snapshot", lambda d, timeout=5.0: SNAP_V2)
    findings = dns_sentinel.run({"domains": ["example.com"]}, state)
    assert any(f.severity == Severity.MEDIUM and "A records" in f.title for f in findings)


def test_ns_drift_is_high(monkeypatch):
    state = {}
    monkeypatch.setattr(dns_sentinel, "snapshot", lambda d, timeout=5.0: SNAP_V1)
    dns_sentinel.run({"domains": ["example.com"]}, state)
    monkeypatch.setattr(dns_sentinel, "snapshot", lambda d, timeout=5.0: SNAP_V3)
    findings = dns_sentinel.run({"domains": ["example.com"]}, state)
    assert any(f.severity == Severity.HIGH and "NS" in f.title for f in findings)


def test_approve_rebaselines(monkeypatch):
    state = {"baselines": {"example.com": SNAP_V1}}
    monkeypatch.setattr(dns_sentinel, "snapshot", lambda d, timeout=5.0: SNAP_V2)
    dns_sentinel.approve(state, "example.com")
    findings = dns_sentinel.run({"domains": ["example.com"]}, state)
    assert findings == []  # new baseline matches -> no drift
