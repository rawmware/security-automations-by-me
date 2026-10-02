"""Sentinel web application — SOC dashboard for the automation engine.

Run:  sentinel web [--host 0.0.0.0] [--port 8000]
"""

from __future__ import annotations

import copy
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import yaml
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import notify as notify_mod
from .. import report as report_mod
from ..findings import Severity
from ..runner import AUTOMATIONS, State, append_jsonl, load_config, run_once
from .db import DB
from .info import AUTOMATION_INFO
from .scheduler import Scheduler

log = logging.getLogger("sentinel.web")

BASE = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE / "templates"))

SECRET_HINTS = ("webhook", "token", "secret", "pass", "key", "auth")


def mask_secrets(obj):
    """Recursively redact secret-looking values for the settings page."""
    if isinstance(obj, dict):
        return {k: ("••••••••" if any(h in k.lower() for h in SECRET_HINTS) and v else mask_secrets(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [mask_secrets(v) for v in obj]
    return obj


class AppContext:
    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self.config = load_config(config_path)
        self.state = State(self.config.get("state_dir", "./state"))
        self.db = DB(Path(self.config.get("state_dir", "./state")) / "sentinel.db")
        self.notifier = notify_mod.Notifier(
            self.config.get("notifications", {}), self.state.load("notify"))
        self.reports_dir = Path(self.config.get("reports_dir", "./reports"))
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.scheduler: Scheduler | None = None

    def effective_automations(self) -> dict:
        """Config automations with UI toggle overrides applied.

        Every known automation gets an entry (possibly empty) so the UI can
        toggle automations that have no YAML section yet.
        """
        overrides = self.state.load("web").get("enabled_overrides", {})
        autos = copy.deepcopy(self.config.get("automations", {}))
        for name in AUTOMATIONS:
            cfg = autos.setdefault(name, {})
            if name in overrides:
                cfg["enabled"] = overrides[name]
        return autos

    def set_enabled(self, name: str, enabled: bool) -> None:
        web = self.state.load("web")
        web.setdefault("enabled_overrides", {})[name] = enabled
        self.state.save("web")

    def run_pass(self, run_id: str | None = None) -> dict:
        """One full engine pass: run, persist, notify, report."""
        import uuid
        run_id = run_id or uuid.uuid4().hex[:8]
        # Fresh config each pass so edits/toggles apply without restart.
        self.config = load_config(self.config_path)
        cfg = dict(self.config)
        cfg["automations"] = self.effective_automations()
        log.info("web run %s starting", run_id)
        self.db.save_run_started(run_id)
        findings, _ = run_once(cfg, self.state)
        self.db.save_run_finished(run_id, findings)
        append_jsonl(self.config.get("events_jsonl",
                                     str(self.reports_dir / "events.jsonl")),
                     findings, run_id)
        for f in findings:
            try:
                self.notifier.send(f)
            except Exception:
                log.exception("notify failed for %r", f.title)
        self.state.save("notify")
        meta = {"run_id": run_id, "at": datetime.now(timezone.utc).isoformat()}
        (self.reports_dir / f"report-{run_id}.md").write_text(
            report_mod.build_markdown(findings, meta))
        (self.reports_dir / f"report-{run_id}.html").write_text(
            report_mod.build_html(findings, meta))
        (self.reports_dir / "report-latest.html").write_text(
            report_mod.build_html(findings, meta))
        log.info("web run %s done: %d findings", run_id, len(findings))
        return {"run_id": run_id, "findings": len(findings)}


ctx: AppContext | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global ctx
    config_path = app.state.config_path
    ctx = AppContext(config_path)
    interval = int(ctx.config.get("interval_minutes", 60))
    scheduler = Scheduler(interval, ctx.run_pass)
    ctx.scheduler = scheduler
    scheduler.start()
    log.info("scheduler started (every %d min)", interval)
    yield
    # daemon thread exits with the process


def create_app(config_path: str = "config/automations.yaml") -> FastAPI:
    app = FastAPI(title="Sentinel", lifespan=lifespan)
    app.state.config_path = config_path
    app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")

    # -- pages ---------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        stats = ctx.db.stats()
        recent = ctx.db.list_findings(limit=10)
        autos = []
        summary = {s["automation"]: s for s in ctx.db.automation_summary()}
        for name in AUTOMATIONS:
            info = AUTOMATION_INFO[name]
            enabled = ctx.effective_automations().get(name, {}).get("enabled", False)
            s = summary.get(name, {})
            autos.append({"name": name, "enabled": enabled, **info,
                          "total": s.get("total", 0), "last_seen": s.get("last_seen")})
        sched = {"next_run_in": ctx.scheduler.next_run_in,
                 "last_run_at": ctx.scheduler.last_run_at} if ctx.scheduler else {}
        return templates.TemplateResponse(request, "dashboard.html", {
            "request": request, "stats": stats, "recent": recent,
            "automations": autos, "sched": sched,
            "now": datetime.now(timezone.utc).isoformat(),
        })

    @app.get("/findings", response_class=HTMLResponse)
    def findings_page(request: Request, severity: str | None = None,
                      automation: str | None = None, q: str | None = None):
        rows = ctx.db.list_findings(severity=severity or None,
                                    automation=automation or None,
                                    q=q or None, limit=300)
        return templates.TemplateResponse(request, "findings.html", {
            "request": request, "findings": rows,
            "f_severity": severity or "", "f_automation": automation or "",
            "f_q": q or "", "severities": [s.label for s in Severity],
            "automations": sorted(AUTOMATIONS),
        })

    @app.get("/findings/{fid}", response_class=HTMLResponse)
    def finding_detail(request: Request, fid: int):
        row = ctx.db.get_finding(fid)
        if not row:
            raise HTTPException(404, "finding not found")
        import json as _json
        try:
            row["evidence_pretty"] = _json.dumps(_json.loads(row["evidence"]),
                                                 indent=2)[:4000]
        except Exception:
            row["evidence_pretty"] = row["evidence"][:4000]
        return templates.TemplateResponse(request, "finding_detail.html",
                                          {"request": request, "f": row})

    @app.get("/automations", response_class=HTMLResponse)
    def automations_page(request: Request):
        eff = ctx.effective_automations()
        summary = {s["automation"]: s for s in ctx.db.automation_summary()}
        autos = []
        for name in AUTOMATIONS:
            s = summary.get(name, {})
            autos.append({"name": name,
                          "enabled": eff.get(name, {}).get("enabled", False),
                          "config": eff.get(name, {}),
                          **AUTOMATION_INFO[name],
                          "total": s.get("total", 0), "last_seen": s.get("last_seen")})
        return templates.TemplateResponse(request, "automations.html",
                                          {"request": request, "automations": autos})

    @app.get("/automations/{name}", response_class=HTMLResponse)
    def automation_detail(request: Request, name: str):
        if name not in AUTOMATIONS:
            raise HTTPException(404, "unknown automation")
        eff = ctx.effective_automations().get(name, {})
        rows = ctx.db.list_findings(automation=name, limit=20)
        return templates.TemplateResponse(request, "automation_detail.html", {
            "request": request, "name": name, "info": AUTOMATION_INFO[name],
            "enabled": eff.get("enabled", False), "config": eff,
            "recent": rows,
        })

    @app.post("/automations/{name}/toggle")
    def toggle_automation(name: str, enabled: str = Form("off")):
        if name not in AUTOMATIONS:
            raise HTTPException(404, "unknown automation")
        ctx.set_enabled(name, enabled == "on")
        return RedirectResponse(f"/automations/{name}", status_code=303)

    @app.get("/runs", response_class=HTMLResponse)
    def runs_page(request: Request):
        return templates.TemplateResponse(request, "runs.html",
                                          {"request": request,
                                           "runs": ctx.db.list_runs()})

    @app.get("/reports", response_class=HTMLResponse)
    def reports_page(request: Request):
        files = sorted(ctx.reports_dir.glob("report-*.html"), reverse=True)[:20]
        return templates.TemplateResponse(request, "reports.html", {
            "request": request,
            "reports": [{"name": f.name,
                         "size": f.stat().st_size,
                         "mtime": datetime.fromtimestamp(
                             f.stat().st_mtime, timezone.utc).isoformat()}
                        for f in files],
        })

    @app.get("/reports/{name}", response_class=HTMLResponse)
    def serve_report(name: str):
        p = (ctx.reports_dir / name).resolve()
        if not str(p).startswith(str(ctx.reports_dir.resolve())) or not p.exists():
            raise HTTPException(404, "report not found")
        return HTMLResponse(p.read_text())

    @app.get("/settings", response_class=HTMLResponse)
    def settings_page(request: Request):
        return templates.TemplateResponse(request, "settings.html", {
            "request": request,
            "config": mask_secrets(ctx.config),
            "config_yaml": yaml.safe_dump(mask_secrets(ctx.config),
                                          sort_keys=False, default_flow_style=False)[:6000],
        })

    # -- actions -------------------------------------------------------
    @app.post("/run")
    def trigger_run():
        ctx.scheduler.trigger()
        return RedirectResponse("/", status_code=303)

    # -- JSON API ------------------------------------------------------
    @app.get("/api/stats", response_class=JSONResponse)
    def api_stats():
        return ctx.db.stats()

    @app.get("/api/findings", response_class=JSONResponse)
    def api_findings(severity: str | None = None, automation: str | None = None,
                     limit: int = 100):
        return ctx.db.list_findings(severity=severity, automation=automation,
                                    limit=min(limit, 500))

    return app
