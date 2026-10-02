# TLS Watch — how it works

Certificate expiry and misconfiguration monitoring via real TLS handshakes.

## Pipeline

For each `host:port` it completes a TLS handshake (with verification
disabled — verification *failures* are findings, not connection errors) and
evaluates the leaf certificate:

1. **Expiry** — ≤14d CRITICAL, ≤30d HIGH, ≤60d MEDIUM. The 60-day tripwire
   exists for 90-day (Let's Encrypt-style) certs: it fires on the *first*
   failed auto-renew, not the day of the outage.
2. **Already expired → CRITICAL.** Browsers hard-fail; this is an outage
   wearing a security label.
3. **Self-signed on a public host → HIGH.** Misdeployed internal cert or
   active MITM infrastructure — either way, wrong.
4. **Weak signature (md5/sha1) → MEDIUM.** Browsers deprecated these years
   ago; presence means ancient tooling.
5. **SAN/CN hostname mismatch → HIGH.** Trains users to click through
   warnings, which is exactly what MITM needs.

Unreachable endpoints produce a MEDIUM "TLS endpoint unreachable" finding
instead of crashing the run.

## Tuning

- Add internal hosts with their ports; the handshake works the same.
- Thresholds are constants in `tls_watch.analyze_cert` — adjust per policy
  (e.g. 90-day internal CA → lower the MEDIUM bar).

## Limitations

- Only the leaf is inspected; chain-building issues are out of scope.
- SNI-based virtual hosts are handled via `server_hostname`; IP-literal
  targets without SNI may return default certs.

## Sec+ mapping

SY0-701 Domain 3.0 — Implementation (PKI, certificate management).
