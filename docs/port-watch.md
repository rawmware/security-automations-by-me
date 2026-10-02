# Port Watch — how it works

Attack-surface drift detection: does the live network match the declared
attack surface?

## Pipeline

1. **Declare** — per host, list `expected_open` (the intended surface) and
   optional `also_check`.
2. **Scan** — TCP-connect each target port plus a watchlist of
   commonly-abused ports (23, 445, 1433, 3306, 3389, 5432, 5900, 6379,
   27017, 9200, 11211, 2375…). Grab up to 1KB of banner on open ports.
3. **Diff**:
   - **Open but not expected → HIGH.** Assume hostile until proven
     otherwise — this is how ransomware finds RDP and how data walks out
     through forgotten database ports.
   - **Expected but closed → MEDIUM.** Service down, or an unannounced
     firewall change.
   - **Banner changed since last run → LOW.** The service behind the port
     changed: upgrade, or replacement with something malicious.

## Design note

This is deliberately *not* a full port scanner. It answers one question —
"does the live attack surface match the declared one?" Full sweeps are for
periodic assessments; drift detection is for every hour.

## Tuning

- `check_abuse_watchlist: false` if you only care about your declared
  ports (faster, quieter).
- `timeout_seconds`: 3s default; raise on high-latency links.

## Limitations

- TCP-connect only: no UDP, no stealth. It's a drift detector, not nmap.
- Banner grabs can trip IDS — expected; allowlist the scanner IP.

## Sec+ mapping

SY0-701 Domain 4.0 — Operations & Incident Response (attack surface
monitoring, continuous monitoring).
