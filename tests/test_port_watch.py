"""Hermetic tests for port_watch (tcp_check monkeypatched)."""

from sentinel import port_watch
from sentinel.findings import Severity

FAKE = {
    80: (True, "nginx/1.24"),
    443: (True, "nginx/1.24"),
    22: (True, "OpenSSH_9.2"),   # unexpected
    3306: (False, None),          # expected but closed
}


def _fake_tcp(host, port, timeout=3.0):
    return FAKE.get(port, (False, None))


def test_unexpected_open_is_high(monkeypatch):
    monkeypatch.setattr(port_watch, "tcp_check", _fake_tcp)
    cfg = {"hosts": [{"host": "example.com", "expected_open": [80, 443, 3306],
                        "also_check": [22]}],
           "check_abuse_watchlist": False}
    findings = port_watch.run(cfg, {})
    by_title = {f.title: f for f in findings}
    assert by_title["Unexpected open port: example.com:22"].severity == Severity.HIGH
    assert by_title["Expected service down: example.com:3306"].severity == Severity.MEDIUM


def test_banner_change_is_low(monkeypatch):
    monkeypatch.setattr(port_watch, "tcp_check", _fake_tcp)
    cfg = {"hosts": [{"host": "example.com", "expected_open": [80, 443]}],
           "check_abuse_watchlist": False}
    state = {"banners": {"example.com": {"80": "nginx/1.20", "443": "nginx/1.24"}}}
    findings = port_watch.run(cfg, state)
    banner = [f for f in findings if "banner changed" in f.title]
    assert len(banner) == 1 and banner[0].severity == Severity.LOW
    assert state["banners"]["example.com"]["80"] == "nginx/1.24"  # state updated


def test_clean_host_no_findings(monkeypatch):
    monkeypatch.setattr(port_watch, "tcp_check",
                        lambda h, p, timeout=3.0: (True, "ok") if p in (80, 443) else (False, None))
    cfg = {"hosts": [{"host": "example.com", "expected_open": [80, 443]}],
           "check_abuse_watchlist": False}
    assert port_watch.run(cfg, {}) == []
