# DNS Sentinel — how it works

DNS baseline and drift detection: catches hijacking, silent mail rerouting,
and unauthorized infrastructure changes.

## Pipeline

1. **Snapshot** — A, AAAA, CNAME, MX, TXT, NS records plus the SOA serial
   (a change canary: serial bumps when the zone is edited).
2. **Baseline** — first run stores the snapshot as known-good and emits one
   INFO finding. Review it once; it becomes the ground truth.
3. **Drift** — every later run diffs live DNS against the baseline:
   - **NS / MX change → HIGH.** NS drift is zone hijack; MX drift silently
     reroutes your mail. Both have total blast radius.
   - **A / AAAA / CNAME → MEDIUM.** Traffic redirection for specific names;
     also the staging signal for subdomain takeover.
   - **TXT → LOW.** SPF/DKIM/verification churn — still worth knowing.
   - **SOA serial bump with identical records → INFO.**
4. **Sticky baseline** — the original baseline is kept until an operator
   explicitly approves the new state (`sentinel approve dns_sentinel
   <domain>` or the dashboard). Drift keeps alerting; it never silently
   re-baselines.

## Tuning

- Run interval is the detection latency. Hourly is sane; 15 min for
  high-value domains (DNS TTLs make sub-5-min pointless).
- If your DNS changes legitimately often (CDN/geo-DNS), scope the watched
  names to the stable ones (apex, mail, vpn) instead of the CDN front.

## Limitations / evasion

- Only sees *public* DNS. Split-horizon/internal zones need an internal
  resolver view pointed at them.
- An attacker with registrar access can change DNS *and* wait out your
  baseline approval — pair with registrar audit-log alerting.

## Sec+ mapping

SY0-701 Domain 2.0 — Architecture & Design (DNS security, zone integrity).
