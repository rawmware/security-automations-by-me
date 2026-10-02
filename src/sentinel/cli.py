"""Command-line interface.

    sentinel init                          # write config/automations.yaml from the example
    sentinel once --automation typo_watch   # single automation, one pass
    sentinel run                             # all enabled automations, one pass
    sentinel run --loop                      # daemon mode (interval from config)
    sentinel report                          # regenerate reports from last run
    sentinel approve dns_sentinel example.com  # accept current DNS as new baseline
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import sys
from pathlib import Path

from . import dns_sentinel
from . import report as report_mod
from .findings import Finding, Severity
from .runner import AUTOMATIONS, State, execute, load_config

EXAMPLE_CONFIG = Path(__file__).resolve().parent.parent.parent / "config" / "automations.example.yaml"


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")


def cmd_init(args) -> int:
    dest = Path(args.config)
    if dest.exists() and not args.force:
        print(f"{dest} exists; use --force to overwrite")
        return 1
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(EXAMPLE_CONFIG, dest)
    print(f"wrote {dest} — edit it, then run: sentinel run --config {dest}")
    return 0


def cmd_once(args) -> int:
    config = load_config(args.config)
    state = State(config.get("state_dir", "./state"))
    name = args.automation
    module = AUTOMATIONS[name]
    auto_cfg = (config.get("automations") or {}).get(name, {})
    st = state.load(name)
    findings = sorted(module.run(auto_cfg, st))
    state.save(name)
    for f in findings:
        print(f"[{f.severity.label:8}] {f.title}")
    if args.report:
        reports_dir = Path(config.get("reports_dir", "./reports"))
        reports_dir.mkdir(parents=True, exist_ok=True)
        (reports_dir / f"{name}-latest.md").write_text(report_mod.build_markdown(findings))
        (reports_dir / f"{name}-latest.html").write_text(report_mod.build_html(findings))
        print(f"reports written to {reports_dir}")
    return 0


def cmd_run(args) -> int:
    return execute(args.config, loop=args.loop)


def cmd_report(args) -> int:
    config = load_config(args.config)
    reports_dir = Path(config.get("reports_dir", "./reports"))
    data = json.loads((reports_dir / "last_findings.json").read_text())
    findings = [Finding(
        automation=d["automation"], title=d["title"],
        severity=Severity.from_name(d["severity"]), description=d["description"],
        evidence=d.get("evidence", {}), recommendation=d.get("recommendation", ""),
        observed_at=d.get("observed_at", ""),
    ) for d in data]
    meta = {"run_id": "regenerated"}
    (reports_dir / "report-latest.md").write_text(report_mod.build_markdown(findings, meta))
    (reports_dir / "report-latest.html").write_text(report_mod.build_html(findings, meta))
    print(f"regenerated reports for {len(findings)} findings in {reports_dir}")
    return 0


def cmd_approve(args) -> int:
    config = load_config(args.config)
    state = State(config.get("state_dir", "./state"))
    if args.automation != "dns_sentinel":
        print("approve is currently only implemented for dns_sentinel")
        return 1
    st = state.load(args.automation)
    print(f"approving current DNS snapshot as new baseline for {args.target} ...")
    dns_sentinel.approve(st, args.target)
    state.save(args.automation)
    print("baseline updated.")
    return 0


def cmd_web(args) -> int:
    import uvicorn

    from .web.app import create_app
    app = create_app(args.config)
    print(f"Sentinel dashboard: http://{args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentinel",
                                description="Defensive security automation toolkit")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("init", help="write a starter config file")
    pi.add_argument("--config", default="config/automations.yaml")
    pi.add_argument("--force", action="store_true")
    pi.set_defaults(func=cmd_init)

    po = sub.add_parser("once", help="run a single automation once")
    po.add_argument("--automation", required=True, choices=sorted(AUTOMATIONS))
    po.add_argument("--config", default="config/automations.yaml")
    po.add_argument("--report", action="store_true", help="write per-automation reports")
    po.set_defaults(func=cmd_once)

    pr = sub.add_parser("run", help="run all enabled automations")
    pr.add_argument("--config", default="config/automations.yaml")
    pr.add_argument("--loop", action="store_true", help="repeat on interval_minutes")
    pr.set_defaults(func=cmd_run)

    pgr = sub.add_parser("report", help="regenerate reports from the last run")
    pgr.add_argument("--config", default="config/automations.yaml")
    pgr.set_defaults(func=cmd_report)

    pa = sub.add_parser("approve", help="accept current state as new baseline")
    pa.add_argument("automation", choices=["dns_sentinel"])
    pa.add_argument("target", help="domain to re-baseline")
    pa.add_argument("--config", default="config/automations.yaml")
    pa.set_defaults(func=cmd_approve)

    pw = sub.add_parser("web", help="start the dashboard web app")
    pw.add_argument("--config", default="config/automations.yaml")
    pw.add_argument("--host", default="127.0.0.1")
    pw.add_argument("--port", type=int, default=8000)
    pw.set_defaults(func=cmd_web)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    _setup_logging(args.verbose)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
