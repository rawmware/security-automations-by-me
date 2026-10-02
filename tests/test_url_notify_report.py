"""Hermetic tests for url_intel, notify, report, findings."""

from sentinel import notify as notify_mod
from sentinel import report as report_mod
from sentinel import url_intel
from sentinel.findings import Finding, Severity


def _finding(sev=Severity.HIGH, title="t"):
    return Finding(automation="url_intel", title=title, severity=sev,
                   description="d", evidence={"k": "v"}, recommendation="r")


# -- url_intel heuristics (pure, no network) ------------------------------

def test_punycode_flagged():
    hits = {r: p for p, r in url_intel.heuristics("http://xn--exmple-cua.com/")}
    assert any("punycode" in r for r in hits)


def test_ip_literal_flagged():
    hits = url_intel.heuristics("http://192.0.2.44/login")
    assert any("IP-literal" in r for _, r in hits)


def test_at_trick_flagged():
    hits = url_intel.heuristics("http://example.com@evil.example/")
    assert any("'@'" in r for _, r in hits)


def test_clean_url_no_hits():
    assert url_intel.heuristics("https://example.com/about") == []


def test_score_url_clean(monkeypatch):
    monkeypatch.setattr(url_intel, "unshorten", lambda u, **k: (u, [u]))
    monkeypatch.setattr(url_intel, "check_urlscan",
                        lambda d, **k: {"scans": 0, "malicious": 0})
    a = url_intel.score_url("https://example.com/about")
    assert a["score"] == 0 and a["severity"] == "INFO"


def test_score_url_malicious_signals(monkeypatch):
    monkeypatch.setattr(url_intel, "unshorten", lambda u, **k: (u, [u]))
    monkeypatch.setattr(url_intel, "check_urlscan",
                        lambda d, **k: {"scans": 3, "malicious": 2})
    a = url_intel.score_url("http://xn--exmple-cua.com/login.php?x=" + "a" * 150)
    assert a["score"] >= 50 and a["severity"] in ("HIGH", "CRITICAL")


# -- findings ---------------------------------------------------------------

def test_dedupe_key_stable():
    assert _finding().dedupe_key() == _finding().dedupe_key()
    assert _finding(title="other").dedupe_key() != _finding().dedupe_key()


def test_sorting_most_severe_first():
    fs = sorted([_finding(Severity.LOW), _finding(Severity.CRITICAL)])
    assert fs[0].severity == Severity.CRITICAL


# -- notify ------------------------------------------------------------------

def test_dedupe_suppresses_repeat():
    n = notify_mod.Notifier({"stdout": {"enabled": False}, "dedupe_hours": 24}, {})
    f = _finding()
    assert n._should_send(f, "discord") is True
    assert n._should_send(f, "discord") is False  # suppressed within window


def test_severity_routing():
    n = notify_mod.Notifier(
        {"discord": {"enabled": True, "min_severity": "CRITICAL"},
         "stdout": {"enabled": False}}, {})
    assert n._should_send(_finding(Severity.HIGH), "discord") is False
    assert n._should_send(_finding(Severity.CRITICAL), "discord") is True


def test_stdout_channel(capsys):
    n = notify_mod.Notifier({"stdout": {"enabled": True, "min_severity": "INFO"},
                             "dedupe_hours": 0}, {})
    n.send(_finding())
    out = capsys.readouterr().out
    assert "HIGH" in out


# -- report -------------------------------------------------------------------

def test_markdown_report_contains_findings():
    md = report_mod.build_markdown([_finding(Severity.CRITICAL, "evil domain")])
    assert "evil domain" in md and "CRITICAL" in md


def test_html_report_structure():
    html = report_mod.build_html([_finding(Severity.HIGH, "evil domain")])
    assert "<html" in html and "evil domain" in html and "HIGH" in html


def test_empty_report_clean_message():
    assert "Clean run" in report_mod.build_markdown([])
