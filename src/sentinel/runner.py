"""runner — orchestrator: config, scheduling, state, SIEM logging, reports.

Pipeline per run:
    load config -> for each enabled automation: run(config, state)
               -> persist state -> append findings to events.jsonl (SIEM-shippable)
               -> notify eligible channels -> write Markdown + HTML reports

State is one JSON file per automation under ``state_dir``. Findings are
append-only JSONL so Splunk/Wazuh/ELK can tail the file directly.
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml

from . import auth_watch, dns_sentinel, notify, port_watch, tls_watch, typo_watch, url_intel
from . import report as report_mod
from .findings import Finding

log = logging.getLogger("sentinel")

AUTOMATIONS = {
    "typo_watch": typo_watch,
    "dns_sentinel": dns_sentinel,
    "tls_watch": tls_watch,
    "port_watch": port_watch,
    "auth_watch": auth_watch,
    "url_intel": url_intel,
}


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def load_config(path: str | Path) -> dict:
    """Load YAML config with ``${ENV_VAR}`` substitution.

    Secrets stay in the environment (or .env); the YAML only references them.
    """
    text = Path(path).read_text()
    text = os.path.expandvars(text)
    cfg = yaml.safe_load(text) or {}
    cfg["_config_path"] = str(path)
    return cfg


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

class State:
    """Per-automation persisted JSON state."""

    def __init__(self, state_dir: str | Path):
        self.dir = Path(state_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, dict] = {}

    def _path(self, name: str) -> Path:
        return self.dir / f"{name}.json"

    def load(self, name: str) -> dict:
        if name not in self._cache:
            p = self._path(name)
            if p.exists():
                try:
                    self._cache[name] = json.loads(p.read_text())
                except json.JSONDecodeError:
                    log.warning("state: %s corrupt, starting fresh", p)
                    self._cache[name] = {}
            else:
                self._cache[name] = {}
        return self._cache[name]

    def save(self, name: str) -> None:
        p = self._path(name)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._cache.get(name, {}), indent=2, default=str))
        tmp.replace(p)


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

def run_once(config: dict, state: State) -> tuple[list[Finding], str]:
    """Execute one pass of every enabled automation. Returns (findings, run_id)."""
    run_id = uuid.uuid4().hex[:8]
    findings: list[Finding] = []
    for name, module in AUTOMATIONS.items():
        auto_cfg = (config.get("automations") or {}).get(name, {})
        if not auto_cfg.get("enabled", False):
            continue
        log.info("run %s: starting %s", run_id, name)
        st = state.load(name)
        try:
            results = module.run(auto_cfg, st)
            log.info("run %s: %s -> %d findings", run_id, name, len(results))
            findings.extend(results)
        except Exception:
            log.exception("run %s: %s crashed", run_id, name)
        finally:
            state.save(name)
    return sorted(findings), run_id


def append_jsonl(path: str | Path, findings: list[Finding], run_id: str) -> None:
    """Append findings as JSONL — tail this file from your SIEM."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a") as fh:
        for f in findings:
            record = f.to_dict()
            record["run_id"] = run_id
            fh.write(json.dumps(record, default=str) + "\n")


def execute(config_path: str | Path, loop: bool = False) -> int:
    """Full pipeline: run automations, log, notify, report. Returns exit code."""
    config = load_config(config_path)
    state = State(config.get("state_dir", "./state"))
    reports_dir = Path(config.get("reports_dir", "./reports"))
    reports_dir.mkdir(parents=True, exist_ok=True)
    events_path = config.get("events_jsonl", str(reports_dir / "events.jsonl"))
    notifier = notify.Notifier(config.get("notifications", {}), state.load("notify"))

    def one_pass() -> int:
        findings, run_id = run_once(config, state)
        append_jsonl(events_path, findings, run_id)
        with (reports_dir / "last_findings.json").open("w") as fh:
            json.dump([f.to_dict() for f in findings], fh, indent=2, default=str)
        meta = {"run_id": run_id,
                "at": datetime.now(timezone.utc).isoformat()}
        (reports_dir / f"report-{run_id}.md").write_text(
            report_mod.build_markdown(findings, meta))
        (reports_dir / f"report-{run_id}.html").write_text(
            report_mod.build_html(findings, meta))
        (reports_dir / "report-latest.md").write_text(
            report_mod.build_markdown(findings, meta))
        (reports_dir / "report-latest.html").write_text(
            report_mod.build_html(findings, meta))
        for f in findings:
            notifier.send(f)
        state.save("notify")
        log.info("run %s: %d findings, reports in %s", run_id, len(findings), reports_dir)
        return 0 if not any(
            f.severity.name in ("CRITICAL", "HIGH") for f in findings) else 2

    if not loop:
        return one_pass()
    interval = int(config.get("interval_minutes", 60)) * 60
    log.info("scheduler: every %d minutes (Ctrl-C to stop)", interval // 60)
    while True:
        try:
            one_pass()
        except Exception:
            log.exception("scheduled pass crashed; continuing")
        time.sleep(interval)
    return 0
