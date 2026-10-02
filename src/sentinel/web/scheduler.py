"""Background scheduler: runs the automation engine on an interval.

A daemon thread so the web process stays a single deployable unit —
no celery, no redis, no extra moving parts. ``trigger()`` wakes it for
an immediate run (the "Run now" button).
"""

from __future__ import annotations

import logging
import threading
import time

log = logging.getLogger("sentinel.web")


class Scheduler(threading.Thread):
    def __init__(self, interval_minutes: int, job, on_first_run=None):
        super().__init__(daemon=True, name="sentinel-scheduler")
        self.interval = max(1, interval_minutes) * 60
        self.job = job  # callable() -> None, does one full pass
        self._wake = threading.Event()
        self._on_first_run = on_first_run
        self.last_run_at: float | None = None
        self.next_run_in: int | None = None

    def trigger(self) -> None:
        self._wake.set()

    def run(self) -> None:
        first = True
        while True:
            if first and self._on_first_run:
                try:
                    self._on_first_run()
                except Exception:
                    log.exception("first-run hook failed")
            first = False
            try:
                self.job()
                self.last_run_at = time.time()
            except Exception:
                log.exception("scheduled pass crashed; will retry next interval")
            self._wake.clear()
            # Sleep in small slices so trigger() wakes promptly.
            deadline = time.time() + self.interval
            while time.time() < deadline:
                self.next_run_in = int(deadline - time.time())
                if self._wake.wait(timeout=min(5, max(1, deadline - time.time()))):
                    break
            self.next_run_in = None
