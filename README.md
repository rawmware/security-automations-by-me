# 🛡️ Sentinel — Security Automation Platform

[![CI](https://github.com/rawmware/security-automations-by-me/actions/workflows/ci.yml/badge.svg)](https://github.com/rawmware/security-automations-by-me/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A defensive security automation platform: six detection engines running on a
schedule behind a dark SOC-style dashboard. It watches your domains, certs,
ports, logs, and URLs — and tells you when something drifts, expires, or
looks hostile.

Built the way a working analyst builds: config-driven, scheduled,
multi-channel alerting, SIEM-shippable event logs, Docker-ready, and tested
(55 tests, CI on 3.10–3.12).

## The automations

| Engine | What it does | Hunts |
|---|---|---|
| **Typo Watch** | Generates ~1,500 lookalikes per domain (12 permutation techniques), checks DNS liveness, MX phishing-capability, and CT logs | Typosquatting, brand impersonation, BEC |
| **DNS Sentinel** | Baselines A/AAAA/CNAME/MX/TXT/NS + SOA, alerts on drift | DNS hijacking, mail rerouting, takeover staging |
| **TLS Watch** | Real handshakes: expiry thresholds, self-signed, weak sigs, hostname mismatch | Lapsed renewals, MITM, warning-fatigue |
| **Port Watch** | Declared attack surface vs live TCP scan + banner tracking | Unexpected exposure (RDP/DB), outages |
| **Auth Watch** | Tails auth logs, sliding-window brute-force/spray detection | Credential stuffing, SSH brute force |
| **URL Intel** | Unshortens, scores 0–100 on heuristics, corroborates via urlscan.io | Phishing links, malware droppers |

Each automation's page in the dashboard explains exactly **how it works** —
detection logic, scoring weights, tuning knobs, and limitations. The
`docs/` folder has the full write-ups, plus a
[CompTIA Security+ domain mapping](docs/sec-plus-mapping.md).

## Quick start

**Docker (recommended):**
```bash
git clone https://github.com/rawmware/security-automations-by-me.git
cd security-automations-by-me
cp .env.example .env          # add your Discord/Slack webhooks
cp config/automations.example.yaml config/automations.yaml  # add your domains
docker compose up -d
# → http://localhost:8000
```

**Local:**
```bash
pip install -e .
sentinel init --config config/automations.yaml   # starter config
# edit config/automations.yaml — add your domains/hosts
sentinel web                                     # → http://127.0.0.1:8000
```

Hit **▶ Run now** in the dashboard for the first pass.

## How it works

```
┌──────────────┐   ┌───────────────┐   ┌──────────────┐   ┌───────────────┐
│  YAML config │──▶│ 6 engines run │──▶│   Findings   │──▶│  Dashboard    │
│  + scheduler │   │ on interval   │   │ scored 0-100 │   │  SQLite + UI  │
└──────────────┘   └───────────────┘   └──────┬───────┘   └───────────────┘
                                             ├─────────▶│ Discord/Slack │
                                             ├─────────▶│ Email (SMTP)  │
                                             ├─────────▶│ events.jsonl  │ (SIEM)
                                             └─────────▶│ HTML/MD report│
```

- **One finding model** (`Finding`: automation, title, severity, description,
  evidence, recommendation) — alerts, SIEM events, and reports all consume
  the same object, so they can never disagree.
- **State** (`state_dir`): DNS baselines, auth-log offsets, banner history,
  alert dedupe. Survives restarts; delete to re-baseline.
- **events.jsonl**: every finding appended as JSON — tail it from
  Splunk/Wazuh/ELK.
- **Alert dedupe**: a persistent condition pages once per `dedupe_hours`,
  not every run.
- **Secrets**: environment only (`${VAR}` in YAML), redacted in the UI.

## CLI

```bash
sentinel web                          # dashboard (default :8000)
sentinel run                          # one pass of all enabled engines
sentinel run --loop                   # daemon mode
sentinel once --automation typo_watch # single engine
sentinel approve dns_sentinel example.com  # accept new DNS baseline
```

## Project structure

```
src/sentinel/
  typo_watch.py  dns_sentinel.py  tls_watch.py
  port_watch.py  auth_watch.py    url_intel.py   # the six engines
  findings.py    # Finding model + severity scale
  notify.py      # Discord/Slack/email/stdout + dedupe
  report.py      # Markdown + HTML reports
  runner.py      # orchestration, state, JSONL, scheduling core
  cli.py         # sentinel command
  web/           # FastAPI dashboard: app, SQLite store, scheduler, UI
config/automations.example.yaml
docs/            # per-engine deep dives + Sec+ mapping + operations
tests/           # 55 hermetic tests (no network)
```

## Security model

- Runs as non-root in Docker; auth log mounted read-only.
- Read-only by design: nothing here blocks, kills, or modifies remote
  systems. Findings carry the exact remediation commands for the operator.
- Outbound only: DNS, HTTPS (crt.sh, urlscan.io), your webhooks.

## License

MIT — see [LICENSE](LICENSE).
