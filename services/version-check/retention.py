"""Retention: stored data is deleted on schedule, whether or not requests arrive.

sweep() deletes failure reports past failure_store.RETENTION and prefix
sightings past prefix_store.RETENTION_DAYS. It runs once in the pre-start
step (db_schema.prepare), then every SWEEP_INTERVAL in each worker, so the
published privacy statement (static/index.html) holds.
"""

import sys
import threading
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

import failure_store
import prefix_store

SWEEP_INTERVAL = timedelta(minutes=5)


def sweep(db_path: Path, now: datetime) -> None:
    failure_store.expire(db_path, now)
    prefix_store.purge(db_path, now)


class Sweeper:
    """Runs sweep() every `interval` on a daemon thread, one per worker.

    A failed sweep is logged with its traceback and retried on the next tick;
    stopping the sweeper would quietly break the retention promise.
    """

    def __init__(self, db_path: Path, interval: timedelta,
                 now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        self.db_path, self.interval, self._now = db_path, interval, now
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="retention-sweeper", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join()

    def _run(self) -> None:
        while not self._stop.wait(self.interval.total_seconds()):
            try:
                sweep(self.db_path, self._now())
            except Exception:
                print(f"retention-sweeper: sweep of {self.db_path} failed; retrying in "
                      f"{self.interval}", file=sys.stderr, flush=True)
                traceback.print_exc()
