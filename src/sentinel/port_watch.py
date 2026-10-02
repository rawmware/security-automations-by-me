"""port_watch — expected-port baseline vs. live TCP scan.

How it works
------------
For each host you declare the ports that *should* be open. Each run:

1. **Scans** the union of expected ports + a watchlist of commonly-abused
   ports (21, 23, 445, 3389, 5900, 6379, 27017, 9200, ...) via TCP connect.
2. **Banners** — on open ports it grabs up to 1KB. Banner changes are
   tracked because a changed banner means the service behind the port
   changed (upgrade, or replacement with something malicious).
3. **Diffs** against the declared baseline:
   - open but NOT expected -> HIGH (unexpected exposure; assume hostile
     until proven otherwise — this is how ransomware finds RDP)
   - expected but closed -> MEDIUM (service down, or firewall change)
   - banner changed since last run -> LOW

This is intentionally NOT a full port scanner. It answers one question:
"does the live attack surface match the declared attack surface?"
See docs/port-watch.md for the full write-up.
"""

from __future__ import annotations

import logging
import socket

from .findings import Finding, Severity

log = logging.getLogger(__name__)

# Ports worth checking even when not declared: the usual suspects for
# misconfiguration-driven compromise.
ABUSE_WATCHLIST = [21, 23, 25, 445, 1433, 3306, 3389, 5432, 5900, 6379,
                   27017, 9200, 11211, 2375, 2376, 8080, 8443]


def tcp_check(host: str, port: int, timeout: float = 3.0) -> tuple[bool, str | None]:
    """TCP connect to host:port. Returns (open, banner_or_None)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(2.0)
            try:
                data = sock.recv(1024)
                banner = data.decode("utf-8", errors="replace").strip()[:200]
            except (TimeoutError, OSError):
                banner = None
            return True, banner or None
    except OSError:
        return False, None


def scan_host(host: str, ports: list[int], timeout: float = 3.0) -> dict[int, dict]:
    """Scan ports on a host. Returns {port: {'open': bool, 'banner': str|None}}."""
    results = {}
    for port in sorted(set(ports)):
        is_open, banner = tcp_check(host, port, timeout)
        results[port] = {"open": is_open, "banner": banner}
    return results


def run(config: dict, state: dict) -> list[Finding]:
    """Run a port_watch pass. State tracks last-seen banners per host."""
    hosts_cfg: list[dict] = config.get("hosts", [])
    timeout: float = config.get("timeout_seconds", 3.0)
    check_abuse: bool = config.get("check_abuse_watchlist", True)
    banners: dict = state.setdefault("banners", {})
    findings: list[Finding] = []

    for entry in hosts_cfg:
        host = entry["host"]
        expected = set(entry.get("expected_open", []))
        extra = set(entry.get("also_check", []))
        targets = sorted(expected | extra | (set(ABUSE_WATCHLIST) if check_abuse else set()))
        log.info("port_watch: scanning %s (%d ports)", host, len(targets))
        results = scan_host(host, targets, timeout)

        host_banners: dict = banners.setdefault(host, {})
        for port, res in results.items():
            evidence = {"host": host, "port": port, "banner": res["banner"]}
            if res["open"] and port not in expected:
                findings.append(Finding(
                    automation="port_watch",
                    title=f"Unexpected open port: {host}:{port}",
                    severity=Severity.HIGH,
                    description=(
                        f"Port {port} on {host} is OPEN but not in the declared "
                        f"baseline {sorted(expected)}. Banner: {res['banner'] or 'none captured'}."
                    ),
                    evidence=evidence,
                    recommendation=(
                        "Identify the listening process (ss -tlnp / netstat). If it is "
                        "not required, close it at the host firewall AND the network "
                        "edge. If it is required, add it to expected_open so future "
                        "runs treat it as known."
                    ),
                ))
            elif not res["open"] and port in expected:
                findings.append(Finding(
                    automation="port_watch",
                    title=f"Expected service down: {host}:{port}",
                    severity=Severity.MEDIUM,
                    description=f"Port {port} on {host} is CLOSED but declared as expected-open.",
                    evidence=evidence,
                    recommendation="Check the service status and host firewall rules; confirm whether the closure was intentional.",
                ))
            elif res["open"]:
                prev = host_banners.get(str(port))
                if prev is not None and prev != res["banner"]:
                    findings.append(Finding(
                        automation="port_watch",
                        title=f"Service banner changed: {host}:{port}",
                        severity=Severity.LOW,
                        description=f"Banner on {host}:{port} changed from {prev!r} to {res['banner']!r}.",
                        evidence={**evidence, "previous_banner": prev},
                        recommendation="Confirm the change maps to a planned upgrade or deployment. If not, investigate the host.",
                    ))
                host_banners[str(port)] = res["banner"]
    return sorted(findings)
