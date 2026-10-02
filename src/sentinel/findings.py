"""Core data model shared by every Sentinel automation.

A Finding is the single unit of output: one detected condition, scored with a
severity, carrying the evidence that proves it and the remediation step that
fixes it. Everything downstream — alerting, SIEM shipping, reports — consumes
this shape, so automations never format their own notifications.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import IntEnum


class Severity(IntEnum):
    """Ordered severity scale. Higher value = more urgent."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name

    @property
    def discord_color(self) -> int:
        """Embed sidebar color used by the Discord notifier."""
        return {
            Severity.INFO: 0x95A5A6,
            Severity.LOW: 0x3498DB,
            Severity.MEDIUM: 0xF1C40F,
            Severity.HIGH: 0xE67E22,
            Severity.CRITICAL: 0xE74C3C,
        }[self]

    @classmethod
    def from_name(cls, name: str) -> Severity:
        return cls[name.strip().upper()]


@dataclass
class Finding:
    """One detected condition from one automation run."""

    automation: str          # e.g. "typo_watch"
    title: str               # one-line summary, used for dedupe
    severity: Severity
    description: str         # what was detected and why it matters
    evidence: dict = field(default_factory=dict)      # machine-readable proof
    recommendation: str = ""  # concrete remediation step
    observed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.label
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)

    def dedupe_key(self) -> str:
        """Stable identity for a finding across runs.

        Same automation + same title + same evidence keys = same finding.
        Used by the notifier so a persistent condition alerts once per
        ``dedupe_hours`` instead of on every scheduled run.
        """
        evidence_sig = json.dumps(self.evidence, sort_keys=True, default=str)
        raw = f"{self.automation}|{self.title}|{evidence_sig}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def __lt__(self, other: Finding) -> bool:
        # Sort most-severe first when findings are sorted().
        return self.severity > other.severity
