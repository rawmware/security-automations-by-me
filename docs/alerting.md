# Alerting — how it works

Multi-channel alerting with severity routing and dedupe. One finding in,
the right people notified, exactly once per window.

## Channels

| Channel | Format | Setup |
|---|---|---|
| Discord | Rich embeds, color-coded by severity, evidence + recommendation inline | `discord.webhook_url` |
| Slack | Webhook with colored attachment | `slack.webhook_url` |
| Email | SMTP with TLS, subject prefixed `[Sentinel SEVERITY]` | `email.*` |
| stdout | One line per finding (container logs) | on by default |

## Routing

Each channel has `min_severity`. A finding is delivered to a channel only
if `finding.severity >= channel.min_severity`. Typical shape:

- Discord/Slack at `MEDIUM` — the SOC feed.
- Email at `HIGH` — the pager.
- stdout at `INFO` — the audit trail.

## Dedupe

`dedupe_hours` (default 24): a persistent condition alerts once per window,
not on every scheduled run. Identity is a stable hash of
automation + title + evidence, so flapping values don't reset it.

## Secrets

Webhook URLs and SMTP credentials live in the environment (`.env`),
referenced from YAML as `${VAR}`. They are never written to state, logs,
or reports, and the Settings page redacts them.

## Failure mode

A failing channel logs the error and continues to the next channel — one
dead webhook never silences the others.
