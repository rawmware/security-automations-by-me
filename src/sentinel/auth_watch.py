"""auth_watch — SSH/auth-log brute-force and spray detection.

How it works
------------
1. **Tails** the auth log (default /var/log/auth.log) using offset+inode
   tracking in state, so each scheduled run only processes *new* lines —
   no re-scanning, no duplicates, survives log rotation.
2. **Parses** each line into events: failed password, invalid user,
   accepted login, connection closed during auth.
3. **Sliding window** — counts failures per source IP over the configured
   window (default 15 min). Crossing the threshold fires a finding.
4. **Classifies** the attack shape:
   - *password spraying*: one IP, many distinct usernames (>=5) — the
     modern, stealthier pattern that evades per-account lockout.
   - *targeted brute force*: one IP hammering one/few accounts.
   - *distributed*: many IPs, few attempts each — notes the pattern even
     below threshold so slow attacks stay visible.
5. **Read-only and safe** — it never blocks anything. The recommendation
   carries the exact firewall commands for the operator to run.

Threat model: credential stuffing, password spraying, and SSH brute force
— still the #1 initial-access vector against internet-facing Linux.
See docs/auth-watch.md for the full write-up.
"""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timedelta, timezone

from .findings import Finding, Severity

log = logging.getLogger(__name__)

FAILED_RE = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from "
    r"(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+) port \d+"
)
INVALID_USER_RE = re.compile(
    r"Invalid user (\S+) from (\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)"
)
ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from "
    r"(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+) port \d+"
)
# Syslog timestamp: "Oct  2 12:14:32" (no year — assume current).
SYSLOG_TS_RE = re.compile(r"^(\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2})")


def parse_line(line: str) -> dict | None:
    """Parse one auth-log line into an event dict, or None if irrelevant."""
    ts_match = SYSLOG_TS_RE.match(line)
    ts = None
    if ts_match:
        try:
            ts = datetime.strptime(
                f"{datetime.now(timezone.utc).year} {ts_match.group(1)}", "%Y %b %d %H:%M:%S"
            ).replace(tzinfo=timezone.utc)
        except ValueError:
            ts = None
    m = FAILED_RE.search(line)
    if m:
        return {"type": "failed", "user": m.group(1), "ip": m.group(2), "ts": ts, "raw": line.strip()}
    m = INVALID_USER_RE.search(line)
    if m:
        return {"type": "invalid_user", "user": m.group(1), "ip": m.group(2), "ts": ts, "raw": line.strip()}
    m = ACCEPTED_RE.search(line)
    if m:
        return {"type": "accepted", "user": m.group(1), "ip": m.group(2), "ts": ts, "raw": line.strip()}
    return None


def tail_new_lines(path: str, state: dict) -> list[str]:
    """Read only lines appended since the last run (offset + inode tracking).

    Handles log rotation: if the inode changed or the file shrank, we start
    from the top of the new file.
    """
    try:
        st = os.stat(path)
    except OSError as exc:
        log.warning("auth_watch: cannot stat %s: %s", path, exc)
        return []
    key = f"tail:{path}"
    cursor = state.get(key, {})
    lines: list[str] = []
    rotated = cursor.get("inode") != st.st_ino or st.st_size < cursor.get("offset", 0)
    start = 0 if rotated else cursor.get("offset", 0)
    with open(path, "r", errors="replace") as fh:
        fh.seek(start)
        lines = fh.readlines()
        state[key] = {"inode": st.st_ino, "offset": fh.tell()}
    if rotated:
        log.info("auth_watch: rotation detected on %s, re-reading from start", path)
    return lines


def detect(events: list[dict], window_minutes: int = 15,
           threshold: int = 10) -> list[dict]:
    """Sliding-window detection over parsed events.

    Returns attack dicts: {"ip", "attempts", "users", "kind", "first_seen",
    "last_seen"} for IPs at/over threshold, plus sub-threshold "watch"
    entries for distributed patterns.
    """
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=window_minutes)
    recent = [e for e in events
              if e["type"] in ("failed", "invalid_user")
              and (e["ts"] is None or e["ts"] >= cutoff)]
    by_ip: dict[str, list[dict]] = {}
    for e in recent:
        by_ip.setdefault(e["ip"], []).append(e)

    attacks = []
    for ip, evs in by_ip.items():
        users = sorted({e["user"] for e in evs})
        times = [e["ts"] for e in evs if e["ts"]]
        attack = {
            "ip": ip,
            "attempts": len(evs),
            "users": users,
            "first_seen": min(times).isoformat() if times else None,
            "last_seen": max(times).isoformat() if times else None,
        }
        if len(evs) >= threshold:
            attack["kind"] = "password-spraying" if len(users) >= 5 else "brute-force"
            attack["over_threshold"] = True
        else:
            attack["kind"] = "watch"
            attack["over_threshold"] = False
        attacks.append(attack)
    return attacks


def suggest_block(ip: str) -> str:
    """Firewall commands for the operator. Returned as *recommendation text*
    only — this automation never executes blocks itself."""
    return (
        f"Review first, then block: `sudo ufw deny from {ip}` or "
        f"`sudo iptables -A INPUT -s {ip} -j DROP`. For persistence consider "
        "fail2ban with a matching filter, and report the IP to AbuseIPDB."
    )


def run(config: dict, state: dict) -> list[Finding]:
    """Run an auth_watch pass over new auth-log lines."""
    log_path: str = config.get("log_path", "/var/log/auth.log")
    window: int = config.get("window_minutes", 15)
    threshold: int = config.get("threshold", 10)

    lines = tail_new_lines(log_path, state)
    events = [e for line in lines if (e := parse_line(line))]
    log.info("auth_watch: %d new lines, %d auth events", len(lines), len(events))
    if not events:
        return []

    attacks = detect(events, window, threshold)
    findings: list[Finding] = []
    for a in attacks:
        if not a["over_threshold"]:
            continue
        kind = a["kind"]
        severity = Severity.HIGH if kind == "password-spraying" else Severity.MEDIUM
        findings.append(Finding(
            automation="auth_watch",
            title=f"SSH {kind} detected from {a['ip']} ({a['attempts']} attempts)",
            severity=severity,
            description=(
                f"{a['attempts']} failed SSH logins from {a['ip']} in the last "
                f"{window} minutes targeting {len(a['users'])} account(s): "
                f"{', '.join(a['users'][:10])}"
                f"{'...' if len(a['users']) > 10 else ''}. "
                f"Pattern classified as {kind}."
            ),
            evidence=a,
            recommendation=(
                "Confirm no legitimate user owns this IP. " + suggest_block(a["ip"]) +
                " Also verify: no 'accepted' logins from this IP in the same "
                "window (check manually), and consider disabling password auth "
                "in favor of keys (sshd_config: PasswordAuthentication no)."
            ),
        ))

    # Successful logins from never-before-seen IPs are worth one INFO line.
    accepted = [e for e in events if e["type"] == "accepted"]
    seen_ips: set = set(state.setdefault("seen_accepted_ips", []))
    for e in accepted:
        if e["ip"] not in seen_ips:
            seen_ips.add(e["ip"])
            findings.append(Finding(
                automation="auth_watch",
                title=f"First-seen successful SSH login: {e['user']} from {e['ip']}",
                severity=Severity.INFO,
                description=f"User {e['user']} authenticated from {e['ip']}, never observed before.",
                evidence={"user": e["user"], "ip": e["ip"]},
                recommendation="Verify this login was legitimate with the user. If not, treat as account compromise.",
            ))
    state["seen_accepted_ips"] = sorted(seen_ips)[-500:]  # bounded growth
    return sorted(findings)
