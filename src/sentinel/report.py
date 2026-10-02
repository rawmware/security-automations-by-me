"""report — Markdown and HTML report generation from findings.

Reports are built from the same Finding objects the notifier consumes, so
the chat alert and the written report can never disagree.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from .findings import Finding, Severity

SEV_COLORS = {
    "CRITICAL": "#e74c3c",
    "HIGH": "#e67e22",
    "MEDIUM": "#f1c40f",
    "LOW": "#3498db",
    "INFO": "#95a5a6",
}


def summarize(findings: list[Finding]) -> dict:
    counts = {sev.label: 0 for sev in Severity}
    for f in findings:
        counts[f.severity.label] += 1
    return counts


def build_markdown(findings: list[Finding], meta: dict | None = None) -> str:
    meta = meta or {}
    counts = summarize(findings)
    lines = [
        "# Sentinel Security Report",
        "",
        (f"_Generated {datetime.now(timezone.utc).isoformat()} | "
         f"run: {meta.get('run_id', 'manual')}_"),
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for sev in reversed(list(Severity)):
        lines.append(f"| {sev.label} | {counts[sev.label]} |")
    lines += ["", f"**Total findings:** {len(findings)}", "", "## Findings", ""]
    if not findings:
        lines.append("_No findings above the configured thresholds. Clean run._")
    for f in sorted(findings):
        lines += [
            f"### [{f.severity.label}] {f.title}",
            "",
            f"- **Automation:** `{f.automation}`",
            f"- **Observed:** {f.observed_at}",
            "",
            f.description,
            "",
        ]
        if f.evidence:
            lines += ["<details>", "<summary>Evidence</summary>", "",
                      "```json",
                      json.dumps(f.evidence, indent=2, default=str)[:3000],
                      "```", "</details>", ""]
        if f.recommendation:
            lines += [f"**Recommendation:** {f.recommendation}", ""]
    return "\n".join(lines)


def build_html(findings: list[Finding], meta: dict | None = None) -> str:
    meta = meta or {}
    counts = summarize(findings)
    cards = "".join(
        f'<div class="card"><span class="badge" style="background:{SEV_COLORS[s]}">'
        f"{s}</span><span class='count'>{counts[s]}</span></div>"
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    )
    items = []
    for f in sorted(findings):
        ev = html.escape(json.dumps(f.evidence, indent=2, default=str)[:3000])
        items.append(f"""
        <section class="finding">
          <h3><span class="badge" style="background:{SEV_COLORS[f.severity.label]}">
            {f.severity.label}</span> {html.escape(f.title)}</h3>
          <p class="meta">{html.escape(f.automation)} &middot; {html.escape(f.observed_at)}</p>
          <p>{html.escape(f.description)}</p>
          <details><summary>Evidence</summary><pre>{ev}</pre></details>
          <p class="rec"><strong>Recommendation:</strong> {html.escape(f.recommendation)}</p>
        </section>""")
    body = "\n".join(items) if items else "<p class='clean'>No findings above threshold. Clean run.</p>"
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Sentinel Security Report</title>
<style>
  body {{ font-family: -apple-system, 'Segoe UI', Roboto, sans-serif; max-width: 960px;
         margin: 2rem auto; padding: 0 1rem; color: #1a1a2e; background: #f7f9fc; }}
  header {{ border-bottom: 3px solid #1a1a2e; padding-bottom: 1rem; margin-bottom: 1.5rem; }}
  .cards {{ display: flex; gap: .75rem; flex-wrap: wrap; margin-bottom: 1.5rem; }}
  .card {{ background: #fff; border-radius: 8px; padding: .6rem 1rem;
           box-shadow: 0 1px 3px rgba(0,0,0,.08); display:flex; gap:.5rem; align-items:center; }}
  .badge {{ color: #fff; font-size: .75rem; font-weight: 700; padding: .2rem .6rem;
            border-radius: 999px; }}
  .count {{ font-size: 1.4rem; font-weight: 700; }}
  .finding {{ background: #fff; border-radius: 8px; padding: 1rem 1.25rem;
              margin-bottom: 1rem; box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
  .finding h3 {{ margin: 0 0 .25rem; font-size: 1.05rem; }}
  .meta {{ color: #666; font-size: .85rem; font-family: monospace; }}
  pre {{ background: #1a1a2e; color: #e0e0ff; padding: .75rem; border-radius: 6px;
        overflow-x: auto; font-size: .8rem; }}
  .rec {{ background: #eef6ff; border-left: 4px solid #3498db; padding: .5rem .75rem; }}
  .clean {{ background:#e8f8ee; border-radius:8px; padding:1rem; }}
</style></head>
<body>
<header><h1>🛡️ Sentinel Security Report</h1>
<p>Generated {html.escape(datetime.now(timezone.utc).isoformat())} &middot;
   run: {html.escape(str(meta.get('run_id', 'manual')))} &middot;
   {len(findings)} finding(s)</p></header>
<div class="cards">{cards}</div>
{body}
</body></html>"""
