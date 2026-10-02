# Operations

Running Sentinel in production: scheduling, SIEM shipping, and care.

## Scheduling

Three supported shapes — pick one:

1. **Daemon** (recommended): `sentinel web` or `sentinel run --loop`.
   The in-process scheduler runs every `interval_minutes`. Single
   deployable unit: no celery, no redis.
2. **systemd timer**: `sentinel run` (one pass, exit code 2 if HIGH+
   findings — wire `OnFailure=` to your pager).
3. **cron**: `*/30 * * * * /opt/sentinel/.venv/bin/sentinel run --config
   /etc/sentinel/automations.yaml`.

Config is re-read on every pass: edit `automations.yaml` and the next run
picks it up with no restart. UI toggles apply immediately.

## SIEM shipping

Every finding is appended to `events_jsonl` (default
`./reports/events.jsonl`) as one JSON object per line:

```json
{"automation": "auth_watch", "severity": "HIGH", "title": "...",
 "evidence": {...}, "run_id": "a79770b4", "observed_at": "..."}
```

Tail it from Splunk (monitor), Wazuh (logcollector → JSON decoder), or
ELK (filebeat). Severity is a top-level string field for easy alerting.

## State

`state_dir` holds one JSON file per automation (baselines, log offsets,
dedupe timestamps) plus `sentinel.db` (findings + runs). Back it up if
you care about baseline continuity; delete it to re-baseline everything.

## Least privilege

- The Docker image runs as a non-root `sentinel` user.
- `auth_watch` needs read access to the auth log: mount it `:ro`.
- Outbound network only: DNS, HTTPS (crt.sh, urlscan.io), and your
  webhook endpoints.

## Upgrading

Pull, rebuild, restart. State schema is additive; old state files keep
working.
