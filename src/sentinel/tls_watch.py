"""tls_watch — TLS certificate expiry and misconfiguration monitoring.

How it works
------------
For each configured host:port it opens a TLS handshake, pulls the leaf
certificate, and evaluates:

1. **Expiry** — days until notAfter. Thresholds: <=14d CRITICAL, <=30d HIGH,
   <=60d MEDIUM. (Renewal pipelines break silently; 60d catches Let's
   Encrypt-style 90-day certs that failed auto-renew on first attempt.)
2. **Already expired** — CRITICAL. Browsers hard-fail; this is an outage
   with a security label.
3. **Self-signed** (issuer == subject) on a public host — HIGH. Either a
   misdeployed internal cert or active MITM infrastructure.
4. **Weak signature algorithm** (md5/sha1) — MEDIUM. Deprecation has been
   enforced by browsers for years; its presence means ancient tooling.
5. **Hostname mismatch** — HIGH. The cert doesn't cover the name clients
   use, which trains users to click through warnings.

Threat model: outages from lapsed renewals, MITM via rogue/self-signed
certs, and warning-fatigue that makes real attacks invisible.
See docs/tls-watch.md for the full write-up.
"""

from __future__ import annotations

import logging
import socket
import ssl
from datetime import datetime, timezone

from .findings import Finding, Severity

log = logging.getLogger(__name__)

WEAK_SIG_ALGS = {"md5withrsaencryption", "md5", "sha1withrsaencryption", "sha1"}


def fetch_cert(host: str, port: int = 443, timeout: float = 10.0) -> dict:
    """Perform a TLS handshake and return parsed leaf-certificate details."""
    ctx = ssl.create_default_context()
    # We inspect the cert ourselves; verification failures are findings,
    # not connection errors.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock, \
            ctx.wrap_socket(sock, server_hostname=host) as tls:
        raw = tls.getpeercert(binary_form=True)
    parsed = ssl._ssl._test_decode_cert(raw)  # stdlib cert decoder
    return {
        "host": host,
        "port": port,
        "subject": dict(x[0] for x in parsed.get("subject", [])),
        "issuer": dict(x[0] for x in parsed.get("issuer", [])),
        "not_before": parsed.get("notBefore"),
        "not_after": parsed.get("notAfter"),
        "serial": parsed.get("serialNumber"),
        "sig_alg": parsed.get("signatureAlgorithm", {}).get("algorithm", "unknown")
        if isinstance(parsed.get("signatureAlgorithm"), dict)
        else str(parsed.get("signatureAlgorithm", "unknown")),
        "san": [v for t, v in parsed.get("subjectAltName", []) if t == "DNS"],
    }


def _parse_asn1_time(value: str) -> datetime:
    """Parse 'Oct  2 12:00:00 2026 GMT' from the stdlib cert decoder."""
    return datetime.strptime(value.strip(), "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=timezone.utc
    )


def analyze_cert(info: dict, now: datetime | None = None) -> list[dict]:
    """Pure evaluation of parsed cert details -> list of issue dicts.

    Kept side-effect free so it is fully unit-testable with fixtures.
    Each issue: {"check": str, "severity": Severity, "detail": str}.
    """
    now = now or datetime.now(timezone.utc)
    issues: list[dict] = []
    host = info.get("host", "unknown")

    try:
        not_after = _parse_asn1_time(info["not_after"])
    except Exception:
        return [{"check": "parse", "severity": Severity.HIGH,
                 "detail": f"Could not parse notAfter for {host}; manual review required."}]

    days_left = (not_after - now).total_seconds() / 86400

    if days_left < 0:
        issues.append({"check": "expired", "severity": Severity.CRITICAL,
                       "detail": f"Certificate for {host} EXPIRED {-days_left:.1f} days ago."})
    elif days_left <= 14:
        issues.append({"check": "expiry", "severity": Severity.CRITICAL,
                       "detail": f"Certificate for {host} expires in {days_left:.1f} days."})
    elif days_left <= 30:
        issues.append({"check": "expiry", "severity": Severity.HIGH,
                       "detail": f"Certificate for {host} expires in {days_left:.1f} days."})
    elif days_left <= 60:
        issues.append({"check": "expiry", "severity": Severity.MEDIUM,
                       "detail": f"Certificate for {host} expires in {days_left:.1f} days."})

    subject, issuer = info.get("subject", {}), info.get("issuer", {})
    if subject and issuer and subject == issuer:
        issues.append({"check": "self-signed", "severity": Severity.HIGH,
                       "detail": f"Certificate for {host} is self-signed."})

    sig_alg = str(info.get("sig_alg", "")).lower()
    if any(weak in sig_alg for weak in WEAK_SIG_ALGS):
        issues.append({"check": "weak-signature", "severity": Severity.MEDIUM,
                       "detail": f"Certificate for {host} uses weak signature algorithm: {info.get('sig_alg')}."})

    san = info.get("san", [])
    cn = subject.get("commonName", "")
    if san and not any(_hostname_matches(host, s) for s in san):
        issues.append({"check": "hostname-mismatch", "severity": Severity.HIGH,
                       "detail": f"Certificate SANs {san} do not cover {host}."})
    elif not san and cn and not _hostname_matches(host, cn):
        issues.append({"check": "hostname-mismatch", "severity": Severity.HIGH,
                       "detail": f"Certificate CN {cn!r} does not cover {host}."})

    info["days_remaining"] = round(days_left, 1)
    return issues


def _hostname_matches(host: str, pattern: str) -> bool:
    host, pattern = host.lower(), pattern.lower()
    if pattern.startswith("*."):
        return host.endswith(pattern[1:]) and host.count(".") == pattern.count(".")
    return host == pattern


def run(config: dict, state: dict) -> list[Finding]:
    """Run a tls_watch pass over configured hosts."""
    targets: list[dict] = config.get("hosts", [])
    findings: list[Finding] = []
    for target in targets:
        host = target["host"]
        port = int(target.get("port", 443))
        try:
            info = fetch_cert(host, port)
        except Exception as exc:
            log.warning("tls_watch: %s:%d unreachable: %s", host, port, exc)
            findings.append(Finding(
                automation="tls_watch",
                title=f"TLS endpoint unreachable: {host}:{port}",
                severity=Severity.MEDIUM,
                description=f"Could not complete a TLS handshake with {host}:{port}: {exc}",
                evidence={"host": host, "port": port, "error": str(exc)},
                recommendation="Check the service is running, the port is open, and the firewall allows inbound TLS.",
            ))
            continue
        for issue in analyze_cert(info):
            findings.append(Finding(
                automation="tls_watch",
                title=f"TLS {issue['check']}: {host}:{port}",
                severity=issue["severity"],
                description=issue["detail"],
                evidence={"host": host, "port": port, **{k: v for k, v in info.items()
                          if k in ("subject", "issuer", "not_after", "serial", "sig_alg", "san", "days_remaining")}},
                recommendation=(
                    "Renew/replace the certificate via your ACME pipeline or CA. "
                    "Verify automation (certbot/systemd timer) actually ran — "
                    "most expiries are broken renewals, not forgotten ones."
                ),
            ))
    return sorted(findings)
