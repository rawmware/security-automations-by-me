"""SQLite persistence for the Sentinel web app.

Two tables:
- findings: every finding from every run (queryable, filterable).
- runs: one row per automation pass, with per-severity counts.

Thread-safe via a single lock; the scheduler thread and web handlers share
one DB instance.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from ..findings import Finding, Severity

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    dedupe_key    TEXT,
    automation    TEXT NOT NULL,
    title         TEXT NOT NULL,
    severity      TEXT NOT NULL,
    description   TEXT NOT NULL,
    evidence      TEXT NOT NULL DEFAULT '{}',
    recommendation TEXT NOT NULL DEFAULT '',
    observed_at   TEXT NOT NULL,
    run_id        TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_automation ON findings(automation);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);

CREATE TABLE IF NOT EXISTS runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        TEXT UNIQUE NOT NULL,
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    findings_total INTEGER NOT NULL DEFAULT 0,
    by_severity   TEXT NOT NULL DEFAULT '{}',
    status        TEXT NOT NULL DEFAULT 'running'
);
"""


class DB:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path))
        conn.row_factory = sqlite3.Row
        return conn

    # -- writes ---------------------------------------------------------
    def save_run_started(self, run_id: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO runs (run_id, started_at, status) VALUES (?,?, 'running')",
                (run_id, now),
            )

    def save_run_finished(self, run_id: str, findings: list[Finding]) -> None:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity.label] = counts.get(f.severity.label, 0) + 1
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as conn:
            conn.execute(
                """UPDATE runs SET finished_at=?, findings_total=?, by_severity=?, status='done'
                   WHERE run_id=?""",
                (now, len(findings), json.dumps(counts), run_id),
            )
            conn.executemany(
                """INSERT INTO findings
                   (dedupe_key, automation, title, severity, description, evidence,
                    recommendation, observed_at, run_id, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                [(
                    f.dedupe_key(), f.automation, f.title, f.severity.label,
                    f.description, json.dumps(f.evidence, default=str),
                    f.recommendation, f.observed_at, run_id, now,
                ) for f in findings],
            )

    # -- reads ----------------------------------------------------------
    def stats(self) -> dict:
        with self._lock, self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"]
            by_sev = {r["severity"]: r["c"] for r in
                      conn.execute("SELECT severity, COUNT(*) c FROM findings GROUP BY severity")}
            n_runs = conn.execute("SELECT COUNT(*) c FROM runs WHERE status='done'").fetchone()["c"]
            last = conn.execute(
                "SELECT run_id, finished_at FROM runs WHERE status='done' ORDER BY id DESC LIMIT 1"
            ).fetchone()
            autos = [r["automation"] for r in
                     conn.execute("SELECT DISTINCT automation FROM findings")]
        full = {s.label: by_sev.get(s.label, 0) for s in Severity}
        return {"total_findings": total, "by_severity": full,
                "runs_completed": n_runs,
                "last_run": dict(last) if last else None,
                "automations_seen": autos}

    def list_findings(self, severity: str | None = None, automation: str | None = None,
                      q: str | None = None, limit: int = 200) -> list[dict]:
        sql = "SELECT * FROM findings WHERE 1=1"
        params: list = []
        if severity:
            sql += " AND severity=?"; params.append(severity.upper())
        if automation:
            sql += " AND automation=?"; params.append(automation)
        if q:
            sql += " AND (title LIKE ? OR description LIKE ?)"; params += [f"%{q}%"] * 2
        sql += " ORDER BY id DESC LIMIT ?"; params.append(limit)
        with self._lock, self._connect() as conn:
            return [dict(r) for r in conn.execute(sql, params)]

    def get_finding(self, fid: int) -> dict | None:
        with self._lock, self._connect() as conn:
            r = conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
            return dict(r) if r else None

    def list_runs(self, limit: int = 50) -> list[dict]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                try:
                    d["by_severity"] = json.loads(d["by_severity"])
                except Exception:
                    d["by_severity"] = {}
                out.append(d)
            return out

    def automation_summary(self) -> list[dict]:
        """Per-automation: total findings, max severity, last seen."""
        with self._lock, self._connect() as conn:
            rows = conn.execute("""
                SELECT automation, COUNT(*) total,
                       MAX(CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3
                                        WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END) maxsev,
                       MAX(observed_at) last_seen
                FROM findings GROUP BY automation""").fetchall()
            return [dict(r) for r in rows]
