# SPDX-License-Identifier: Apache-2.0
"""B-01: every reader of a deploy-writable state/ file goes through
fs_nofollow.read_text_nofollow. Root runs these (the health timer's
check-all, the scan, auto-update), and deploy can put anything at the
names: a FIFO must be refused without blocking, a symlink must not be read
through, and a file past the size cap must not be read into memory.

Each reader is given a valid record at its own name first (the baseline);
the same record behind a symlink must then not give the same answer, and a
FIFO there must not block."""
from __future__ import annotations

import json
import os
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from boxmunge import fs_nofollow
from boxmunge.bind_sources import read_record
from boxmunge.blocked_update import read_blocked_state
from boxmunge.container_update_targets import read_target_state
from boxmunge.cve import (
    breaker, grace, kev, kev_source_history, kev_withdrawals, quarantine, scan_state,
)
from boxmunge.discovery_freshness import stale_discovery_warning
from boxmunge.health_checks.container_updates import check_container_updates
from boxmunge.notify import _unconfigured_logged_recently
from boxmunge.os_update_alert import read_os_update_state
from boxmunge.paths import BoxPaths
from boxmunge.project_alerts import alert_state, alert_once
from boxmunge import start_alerts
from boxmunge.state import StateError, read_state

P = "myapp"
NOW = datetime.now(timezone.utc)
ISO = NOW.isoformat()


@dataclass(frozen=True)
class Reader:
    name: str
    path: Callable[[BoxPaths], Path]
    record: Any                       # what a valid file there holds
    read: Callable[[BoxPaths], Any]   # the reader, as root calls it


def _alerted(paths: BoxPaths) -> bool:
    sent: list[str] = []
    import boxmunge.project_alerts as pa
    real = pa.notify
    pa.notify = lambda *a, **k: sent.append("x") or True  # type: ignore[assignment]
    try:
        alert_once(paths, P, "production-down", {"k": 1}, title="t", message="m", component="c")
    finally:
        pa.notify = real  # type: ignore[assignment]
    return bool(sent)


READERS = [
    Reader("read_state", lambda p: p.project_deploy_state(P), {"current_ref": "v1"},
           lambda p: read_state(p.project_deploy_state(P))),
    Reader("quarantine", lambda p: p.project_quarantine_state(P), {"cve": "CVE-1"},
           lambda p: quarantine.read_quarantine_state(P, p)),
    Reader("scan_problem", lambda p: p.project_scan_state(P), {"scanned_at": ISO},
           lambda p: scan_state.scan_problem(p.project_scan_state(P), P, NOW)),
    Reader("breaker.read_held", breaker.breaker_path, {"held": {P: ["CVE-1"]}},
           breaker.read_held),
    Reader("breaker.alert_pending", breaker.breaker_path, {"held": {}, "alert_pending": True},
           breaker.alert_pending),
    Reader("grace", grace.grace_state_path,
           {"installed_at": ISO, "expires_at": ISO, "heads_up_sent": True},
           grace.read_grace_state),
    Reader("kev", lambda p: p.kev_catalog, {"cve_ids": ["CVE-1"], "fetched_at": ISO},
           lambda p: kev.load_kev(p).cve_ids),
    Reader("kev_withdrawals", lambda p: p.kev_withdrawn,
           {"withdrawn": {"CVE-1": {"source": "cisa", "at": ISO}}},
           kev_withdrawals.load_withdrawals),
    Reader("kev_source_history", lambda p: p.kev_sources,
           {"sources": {"https://cisa.example/kev.json":
                        {"released_at": ISO, "disagreed_runs": 0}}},
           kev_source_history.load_history),
    Reader("blocked_update", lambda p: p.platform_update_state,
           {"checked_at": ISO, "current_version": "0.1.0", "blocked": None, "alerted": None},
           read_blocked_state),
    Reader("os_update", lambda p: p.os_update_state,
           {"checked_at": ISO, "problems": [], "alerted": None}, read_os_update_state),
    Reader("discovery", lambda p: p.update_discovery_state,
           {"answered_at": "2000-01-01T00:00:00+00:00", "failing_since": None,
            "last_error": None},
           lambda p: stale_discovery_warning(p, now=NOW)),
    Reader("container_update_target", lambda p: p.container_update_target_state("t"),
           {"last_status": "ok"}, lambda p: read_target_state(p, "t")),
    Reader("health container_updates", lambda p: p.container_update_target_state("t"),
           {"last_status": "failed", "last_check": ISO},
           lambda p: check_container_updates(p).detail),
    Reader("bind_sources", lambda p: p.project_bind_record(P),
           {"version": 2, "sources": {}, "control": {}}, lambda p: read_record(p.project_bind_record(P), redo="redeploy")),
    Reader("notify unconfigured", lambda p: p.alerts_unconfigured_state, {"logged_at": ISO},
           lambda p: _unconfigured_logged_recently(p, NOW)),
    Reader("start_alerts", lambda p: p.state / "start-refused" / f"{P}.json",
           {start_alerts.hashlib.sha256(b"r").hexdigest()[:16]: ISO},
           lambda p: start_alerts.alerted_recently(p, P, "r", NOW)),
    Reader("project_alerts", lambda p: alert_state(p, P, "production-down"), {"key": {"k": 1}}, _alerted),
]


def _outcome(fn: Callable[[], Any], fifo: Path | None = None, seconds: float = 5.0) -> Any:
    """("value", v) or ("raised", type name); a call still blocked after
    `seconds` is released by opening the FIFO for writing and fails."""
    out: dict[str, Any] = {}

    def run() -> None:
        try:
            out["v"] = ("value", fn())
        except Exception as e:  # noqa: BLE001 - the outcome is compared
            out["v"] = ("raised", type(e).__name__)
    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive():
        assert fifo is not None
        os.close(os.open(fifo, os.O_RDWR | os.O_NONBLOCK))
        worker.join(seconds)
        pytest.fail(f"the reader blocked on the FIFO at {fifo}")
    return out["v"]


def _write(path: Path, record: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record))


@pytest.fixture(params=READERS, ids=[r.name for r in READERS])
def reader(request) -> Reader:
    return request.param


def test_the_baseline_record_is_read(paths, reader) -> None:
    """Guards the other tests: a valid record at the name gives an answer."""
    _write(reader.path(paths), reader.record)
    assert _outcome(lambda: reader.read(paths))[0] == "value"


def test_a_symlink_at_the_name_is_not_read_through(paths, tmp_path, reader) -> None:
    path = reader.path(paths)
    _write(path, reader.record)
    baseline = _outcome(lambda: reader.read(paths))
    target = tmp_path / "planted.json"
    os.replace(path, target)
    path.symlink_to(target)
    assert _outcome(lambda: reader.read(paths)) != baseline


def test_a_fifo_at_the_name_does_not_block(paths, reader) -> None:
    path = reader.path(paths)
    path.parent.mkdir(parents=True, exist_ok=True)
    os.mkfifo(path)
    _outcome(lambda: reader.read(paths), fifo=path)


def test_a_file_past_the_cap_is_refused(tmp_path, monkeypatch) -> None:
    path = tmp_path / "big.json"
    path.write_text("x" * 11)
    assert fs_nofollow.read_text_nofollow(path, limit=11) == "x" * 11
    with pytest.raises(OSError, match="larger than 10 bytes"):
        fs_nofollow.read_text_nofollow(path, limit=10)


def test_read_state_reports_a_link_as_a_state_error(paths, tmp_path) -> None:
    target = tmp_path / "elsewhere.json"
    target.write_text("{}")
    path = paths.project_deploy_state(P)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(target)
    with pytest.raises(StateError, match="symlink"):
        read_state(path)


def test_read_state_of_a_missing_file_is_the_default(paths) -> None:
    assert read_state(paths.project_deploy_state(P), {"a": 1}) == {"a": 1}


@pytest.mark.parametrize("path, read, error", [
    (lambda p: p.kev_withdrawn, kev_withdrawals.load_withdrawals,
     kev_withdrawals.KevWithdrawalsError),
    (lambda p: p.kev_sources, kev_source_history.load_history,
     kev_source_history.KevHistoryError),
], ids=["kev_withdrawals", "kev_source_history"])
def test_a_dangling_link_is_not_read_as_no_record(paths, tmp_path, path, read, error) -> None:
    """An empty answer from these records lifts a withdrawal hold or lets a
    lagging KEV source roll the catalog back, so a link whose target is gone
    must fail closed, not read as "no record yet"."""
    link = path(paths)
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(tmp_path / "gone.json")
    with pytest.raises(error):
        read(paths)
