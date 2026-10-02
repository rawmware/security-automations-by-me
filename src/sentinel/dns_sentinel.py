"""dns_sentinel — DNS record baseline and drift detection.

How it works
------------
1. **Snapshot** the public DNS footprint of each watched domain:
   A, AAAA, CNAME, MX, TXT, NS (and the SOA serial as a change canary).
2. **Baseline** — the first run stores the snapshot as the known-good
   baseline and emits a single INFO finding. Nothing is alerted yet.
3. **Drift** — every later run diffs the live snapshot against the
   baseline. Any added/removed/changed record becomes a finding, with
   severity driven by record type:
   - NS / MX change -> HIGH (zone hijack or mail rerouting — the two
     DNS attacks that end in full compromise)
   - A / AAAA / CNAME change -> MEDIUM (possible hijack, CDN rotation, or
     unauthorized subdomain takeover staging)
   - TXT change -> LOW (SPF/DKIM/verification churn; still worth knowing)
   - SOA serial bump alone -> INFO (zone edited, records identical)

Threat model: DNS hijacking, subdomain takeover staging, silent mail
rerouting (MX), and unauthorized infrastructure changes.
See docs/dns-sentinel.md for the full write-up.
"""

from __future__ import annotations

import logging

from .findings import Finding, Severity

log = logging.getLogger(__name__)

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]

# Severity per record type when it drifts. NS/MX are HIGH because they
# redirect *authority* (whole zone) and *mail flow* — the blast radius is
# total. A/AAAA/CNAME are MEDIUM: they redirect traffic for specific names.
SEVERITY_BY_TYPE = {
    "NS": Severity.HIGH,
    "MX": Severity.HIGH,
    "A": Severity.MEDIUM,
    "AAAA": Severity.MEDIUM,
    "CNAME": Severity.MEDIUM,
    "TXT": Severity.LOW,
}


def snapshot(domain: str, timeout: float = 5.0) -> dict:
    """Take a point-in-time snapshot of a domain's public DNS footprint."""
    import dns.resolver
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    snap: dict = {}
    for rdtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rdtype)
            snap[rdtype] = sorted(str(r).rstrip(".") for r in answers)
        except Exception:
            snap[rdtype] = []
    try:
        soa = resolver.resolve(domain, "SOA")
        snap["SOA"] = [str(soa[0]).split()[2]]  # serial is the 3rd field
    except Exception:
        snap["SOA"] = []
    return snap


def diff_records(old: dict, new: dict) -> dict[str, dict[str, list[str]]]:
    """Diff two snapshots. Returns {rdtype: {'added': [...], 'removed': [...]}}."""
    drift: dict[str, dict[str, list[str]]] = {}
    for rdtype in set(old) | set(new):
        old_set, new_set = set(old.get(rdtype, [])), set(new.get(rdtype, []))
        added, removed = sorted(new_set - old_set), sorted(old_set - new_set)
        if added or removed:
            drift[rdtype] = {"added": added, "removed": removed}
    return drift


def run(config: dict, state: dict) -> list[Finding]:
    """Run a dns_sentinel pass. ``state`` persists baselines between runs
    as ``{domain: snapshot}`` under the automation's state key."""
    domains: list[str] = config.get("domains", [])
    baselines: dict = state.setdefault("baselines", {})
    findings: list[Finding] = []

    for domain in domains:
        current = snapshot(domain)
        baseline = baselines.get(domain)
        if baseline is None:
            baselines[domain] = current
            findings.append(Finding(
                automation="dns_sentinel",
                title=f"DNS baseline established for {domain}",
                severity=Severity.INFO,
                description=(
                    f"First observation of {domain}'s public DNS footprint. "
                    "This snapshot is now the known-good baseline; future "
                    "runs will alert on any drift."
                ),
                evidence={"domain": domain, "snapshot": current},
                recommendation="Review the baseline once to confirm it matches your intended DNS configuration.",
            ))
            continue

        drift = diff_records(baseline, current)
        if not drift:
            log.info("dns_sentinel: %s unchanged", domain)
            continue

        for rdtype, change in sorted(drift.items()):
            if rdtype == "SOA":
                severity = Severity.INFO  # serial bumped but records identical
                title = f"DNS zone serial changed for {domain} (records identical)"
            else:
                severity = SEVERITY_BY_TYPE.get(rdtype, Severity.MEDIUM)
                title = f"DNS drift on {domain}: {rdtype} records changed"
            findings.append(Finding(
                automation="dns_sentinel",
                title=title,
                severity=severity,
                description=(
                    f"{rdtype} records for {domain} differ from baseline. "
                    f"Added: {change['added'] or 'none'}. "
                    f"Removed: {change['removed'] or 'none'}."
                ),
                evidence={"domain": domain, "record_type": rdtype, **change},
                recommendation=(
                    "Verify the change was authorized (registrar audit log, "
                    "change ticket). If not: assume compromise — rotate DNS "
                    "provider credentials, re-point records, check for "
                    "newly-issued TLS certs (CT logs), and review mail flow "
                    "for MX changes."
                ),
            ))
        # Re-baseline only on clean, reviewed runs? No — keep the ORIGINAL
        # baseline so drift keeps alerting until an operator approves the new
        # state via `sentinel approve dns_sentinel <domain>`.
    return sorted(findings)


def approve(state: dict, domain: str, current: dict | None = None) -> None:
    """Operator workflow: accept the current snapshot as the new baseline."""
    baselines: dict = state.setdefault("baselines", {})
    if current is None:
        current = snapshot(domain)
    baselines[domain] = current
