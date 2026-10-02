"""Sentinel — defensive security automation toolkit.

Every automation in this package follows the same contract:

    findings: list[Finding] = module.run(config_dict, state_dict)

``config_dict`` comes from ``config/automations.yaml`` (the section for that
automation). ``state_dict`` is that automation's persisted state from the
previous run (may be empty on first run). Each automation returns a list of
:class:`Finding` objects; the runner handles alerting, logging, and reports.
"""

from .findings import Finding, Severity

__all__ = ["Finding", "Severity"]
__version__ = "1.0.0"
