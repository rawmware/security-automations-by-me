"""notify — multi-channel alerting with severity routing and dedupe.

Channels: Discord (rich embeds), Slack (webhook), email (SMTP), stdout.
Every finding at/above a channel's ``min_severity`` is delivered; anything
already alerted within ``dedupe_hours`` is suppressed so a persistent
condition pages once, not every run. Dedupe state lives in the runner's
state store under the "notify" key.
"""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage

import requests

from .findings import Finding, Severity

log = logging.getLogger(__name__)


class Notifier:
    def __init__(self, config: dict, state: dict):
        self.config = config or {}
        self.state = state  # persisted; dedupe timestamps live here

    # -- routing ---------------------------------------------------------
    def _channels(self) -> dict:
        return {
            "discord": self._send_discord,
            "slack": self._send_slack,
            "email": self._send_email,
            "stdout": self._send_stdout,
        }

    def _min_severity(self, channel: str) -> Severity:
        cfg = self.config.get(channel, {})
        return Severity.from_name(cfg.get("min_severity", "HIGH"))

    def _should_send(self, finding: Finding, channel: str) -> bool:
        import time
        if finding.severity < self._min_severity(channel):
            return False
        dedupe_hours = float(self.config.get("dedupe_hours", 24))
        if dedupe_hours <= 0:
            return True
        sent = self.state.setdefault("sent", {})
        key = f"{channel}:{finding.dedupe_key()}"
        last = sent.get(key, 0)
        if time.time() - last < dedupe_hours * 3600:
            return False
        sent[key] = time.time()
        return True

    def send(self, finding: Finding) -> list[str]:
        """Deliver a finding to all eligible channels. Returns channels used."""
        used = []
        for name, sender in self._channels().items():
            if name == "stdout" and not self.config.get("stdout", {}).get("enabled", True):
                continue
            if name != "stdout" and not self.config.get(name, {}).get("enabled"):
                continue
            if not self._should_send(finding, name):
                continue
            try:
                sender(finding)
                used.append(name)
            except Exception as exc:
                log.error("notify: %s failed for %r: %s", name, finding.title, exc)
        return used

    # -- channel implementations ------------------------------------------
    def _send_discord(self, finding: Finding) -> None:
        url = self.config["discord"]["webhook_url"]
        fields = [
            {"name": "Automation", "value": finding.automation, "inline": True},
            {"name": "Observed", "value": finding.observed_at, "inline": True},
        ]
        evidence = finding.evidence
        if isinstance(evidence, dict) and evidence:
            preview = "\n".join(f"{k}: {v}" for k, v in list(evidence.items())[:6])
            fields.append({"name": "Evidence", "value": f"```{preview[:900]}```",
                           "inline": False})
        payload = {"embeds": [{
            "title": f"[{finding.severity.label}] {finding.title}",
            "description": (finding.description[:1800]
                            + (finding.recommendation and
                               f"\n\n**Recommendation:** {finding.recommendation[:600]}")),
            "color": finding.severity.discord_color,
            "fields": fields,
            "timestamp": finding.observed_at,
        }]}
        resp = requests.post(url, json=payload, timeout=10)
        resp.raise_for_status()

    def _send_slack(self, finding: Finding) -> None:
        url = self.config["slack"]["webhook_url"]
        payload = {
            "text": f"[{finding.severity.label}] {finding.title}",
            "attachments": [{
                "color": "danger" if finding.severity >= Severity.HIGH else "warning",
                "text": finding.description[:1500],
                "fields": [
                    {"title": "Automation", "value": finding.automation, "short": True},
                    {"title": "Observed", "value": finding.observed_at, "short": True},
                ],
                "footer": f"Recommendation: {finding.recommendation[:300]}",
            }],
        }
        resp = requests.post(url, json=payload, timeout=10)
        resp.raise_for_status()

    def _send_email(self, finding: Finding) -> None:
        cfg = self.config["email"]
        msg = EmailMessage()
        msg["Subject"] = f"[Sentinel {finding.severity.label}] {finding.title}"
        msg["From"] = cfg["from"]
        msg["To"] = cfg["to"]
        msg.set_content(
            f"{finding.description}\n\nAutomation: {finding.automation}\n"
            f"Observed: {finding.observed_at}\n\n"
            f"Recommendation:\n{finding.recommendation}\n"
        )
        with smtplib.SMTP(cfg["smtp_host"], int(cfg.get("smtp_port", 587)),
                          timeout=15) as smtp:
            smtp.starttls()
            if cfg.get("smtp_user"):
                smtp.login(cfg["smtp_user"], cfg.get("smtp_pass", ""))
            smtp.send_message(msg)

    def _send_stdout(self, finding: Finding) -> None:
        print(f"[{finding.severity.label:8}] {finding.automation:12} {finding.title}")
