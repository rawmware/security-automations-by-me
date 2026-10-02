"""Hermetic tests for tls_watch (pure analyze_cert with fixtures)."""

from datetime import datetime, timedelta, timezone

from sentinel.findings import Severity
from sentinel.tls_watch import _hostname_matches, analyze_cert


def _info(days_left=None, expired_days=None, self_signed=False,
          sig_alg="sha256WithRSAEncryption", san=("example.com",), host="example.com"):
    now = datetime.now(timezone.utc)
    if expired_days is not None:
        not_after = now - timedelta(days=expired_days)
    else:
        not_after = now + timedelta(days=days_left if days_left is not None else 90)
    fmt = not_after.strftime("%b %d %H:%M:%S %Y GMT")
    subj = {"commonName": host}
    issr = dict(subj) if self_signed else {"commonName": "Test CA"}
    return {"host": host, "port": 443, "subject": subj, "issuer": issr,
            "not_after": fmt, "serial": "01", "sig_alg": sig_alg,
            "san": list(san)}


def _checks(info, **kw):
    return {i["check"]: i for i in analyze_cert(info, **kw)}


def test_expired_is_critical():
    issues = _checks(_info(expired_days=3))
    assert issues["expired"]["severity"] == Severity.CRITICAL


def test_expiry_thresholds():
    assert _checks(_info(days_left=10))["expiry"]["severity"] == Severity.CRITICAL
    assert _checks(_info(days_left=20))["expiry"]["severity"] == Severity.HIGH
    assert _checks(_info(days_left=45))["expiry"]["severity"] == Severity.MEDIUM
    assert "expiry" not in _checks(_info(days_left=90))


def test_self_signed_is_high():
    issues = _checks(_info(days_left=90, self_signed=True))
    assert issues["self-signed"]["severity"] == Severity.HIGH


def test_weak_signature():
    issues = _checks(_info(days_left=90, sig_alg="sha1WithRSAEncryption"))
    assert issues["weak-signature"]["severity"] == Severity.MEDIUM


def test_hostname_mismatch():
    issues = _checks(_info(days_left=90, san=("other.com",), host="example.com"))
    assert issues["hostname-mismatch"]["severity"] == Severity.HIGH


def test_hostname_matching():
    assert _hostname_matches("a.example.com", "*.example.com")
    assert _hostname_matches("example.com", "example.com")
    assert not _hostname_matches("deep.a.example.com", "*.example.com")
    assert not _hostname_matches("example.com", "other.com")
