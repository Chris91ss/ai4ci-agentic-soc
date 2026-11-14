"""Live mode: the SOC pipeline as a service consuming the event broker.

The simulator runs separately (``soc simulate --broker ... --speed N``) and applies the
containment actions the pipeline publishes. Time is the stream's: the ``sim_ts`` arrival
time of the newest event.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable

from agentic_soc.pipeline.core import SocPipeline

log = logging.getLogger(__name__)


def run_live(
    pipeline: SocPipeline,
    stop: threading.Event | None = None,
    poll_timeout: float = 0.5,
    report_every_s: float = 10.0,
    on_report: Callable[[SocPipeline], None] | None = None,
    idle_exit_s: float | None = None,
) -> None:
    """Consume until ``stop`` is set (or the stream has been idle for ``idle_exit_s``)."""
    stop = stop or threading.Event()
    last_report = last_event = time.monotonic()
    try:
        while not stop.is_set():
            n = pipeline.step(timeout=poll_timeout)
            now = time.monotonic()
            if n:
                last_event = now
            elif idle_exit_s is not None and now - last_event > idle_exit_s:
                log.info("stream idle for %.0fs; stopping", idle_exit_s)
                break
            if on_report is not None and now - last_report >= report_every_s:
                last_report = now
                on_report(pipeline)
    finally:
        pipeline.flush()
        pipeline.close()
