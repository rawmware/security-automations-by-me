# Auth Watch — how it works

SSH/auth-log brute-force and password-spray detection. Still the #1
initial-access vector against internet-facing Linux.

## Pipeline

1. **Tail** — reads only new lines since the last run using offset+inode
   tracking in state. Survives log rotation (inode change or shrink →
   re-read from top). No re-scanning, no duplicates.
2. **Parse** — failed passwords/publickeys, invalid users, accepted logins
   → structured events `{type, user, ip, ts}`.
3. **Sliding window** — failures per source IP over `window_minutes`
   (default 15). Crossing `threshold` (default 10) fires.
4. **Classify the shape**:
   - **password-spraying** (HIGH): one IP, ≥5 distinct usernames — the
     modern stealthy pattern that evades per-account lockout.
   - **brute-force** (MEDIUM): one IP hammering one/few accounts.
   - Sub-threshold distributed activity is noted as `watch` in evidence.
5. **First-seen successes → INFO.** A successful login from a never-before-
   observed IP is the earliest possible compromise signal.

## Safety

Read-only by design — it never blocks anything. The finding carries the
exact commands (`ufw deny from …` / `iptables … -j DROP`) for the operator,
plus the hardening fix that actually ends the class: `PasswordAuthentication
no` in sshd_config.

## Tuning

- `threshold`/`window_minutes` to your SSH exposure. Internet-facing: 10/15.
  Behind VPN/bastion: lower the threshold, since any failure is suspicious.
- `log_path`: `/var/log/auth.log` (Debian), `/var/log/secure` (RHEL).

## Limitations

- Only as good as the log: if auth logging is off or shipped elsewhere,
  point `log_path` (or the Docker `:ro` mount) at the right file.
- Slow-drip attacks under the threshold stay `watch`-level — pair with
  longer-window SIEM rules for those.

## Sec+ mapping

SY0-701 Domain 4.0 — Operations & Incident Response (log analysis,
account attacks).
