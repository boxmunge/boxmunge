# SPDX-License-Identifier: Apache-2.0
"""B-01: every reader of a deploy-writable state/ file goes through
fs_nofollow.read_text_nofollow. Root runs these (the health timer's
check-all, the scan, auto-update), and deploy can put anything at the
names: a FIFO must be refused without blocking, a symlink must not be read
through, and a file past the size cap must not be read into memory.

Each reader is given a valid record at its own name first (the baseline);
the same record behind a symlink must then not give the same answer, and a
FIFO there must not block. A link whose target is gone is not "no record":
each reader refuses it, or does what it does with a record it cannot read
(see `dangling` on each row), never what it does when nothing is there
(fs_nofollow.read_text_nofollow_or_none is the one existence rule)."""
from __future__ import annotations

import json
import os
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from boxmunge import (
    bind_sources, data_dirs, fs_nofollow, pause, release, release_txn, run_as,
    staged_release, unresolved_stage, upgrade_state, user_drift,
)
from boxmunge.backup_evidence import project_evidence, sync_evidence
from boxmunge.bind_sources import read_record
from boxmunge.blocked_update import read_blocked_state
from boxmunge.commands.security_scan_inputs import project_suppressions_path
from boxmunge.container_update_targets import read_target_state
from boxmunge.cve import (
    breaker, kev, kev_source_history, kev_withdrawals, quarantine, scan_state,
    suppressions,
)
from boxmunge.discovery_freshness import stale_discovery_warning
from boxmunge.health_checks.backup_freshness import check_backup_freshness
from boxmunge.health_checks.container_updates import check_container_updates
from boxmunge.notify import _unconfigured_logged_recently
from boxmunge.os_update_alert import read_os_update_state
from boxmunge.paths import BoxPaths
from boxmunge.project_registry import unfinished_removals
from boxmunge.project_alerts import alert_state, alert_once
from boxmunge import start_alerts
from boxmunge.state import StateError, read_state

P = "myapp"
NOW = datetime.now(timezone.utc)
ISO = NOW.isoformat()


Outcome = tuple[str, Any]   # ("value", v) or ("raised", type name)


def _refused(outcome: Outcome, _paths: BoxPaths) -> bool:
    return outcome[0] == "raised"


def _logged_unreadable(outcome: Outcome, paths: BoxPaths, value: Any) -> bool:
    """An alert throttle: a record it cannot read means "not alerted yet"
    (the alert goes out and the record is rewritten), said in the log."""
    return outcome == ("value", value) and "unreadable" in paths.log_file.read_text()


@dataclass(frozen=True)
class Reader:
    name: str
    path: Callable[[BoxPaths], Path]
    record: Any                       # what a valid file there holds
    read: Callable[[BoxPaths], Any]   # the reader, as root calls it
    # Whether its outcome with a dangling link at the name is the specified one.
    dangling: Callable[[Outcome, BoxPaths], bool] = _refused


def _live_ref(paths: BoxPaths) -> Any:
    """With no live.json, the deploy record names the release (projects
    deployed before .releases/); a dangling live.json must not fall to it."""
    _write(paths.project_deploy_state(P), {"current_ref": "v0"})
    return release.live_ref(paths, P)


def _previous_release(paths: BoxPaths) -> Any:
    release.previous_dir(paths, P).mkdir(parents=True, exist_ok=True)
    return release.load_previous_release(paths, P)


def _backup_freshness(paths: BoxPaths) -> str:
    """The check reads the records of deployed projects only."""
    paths.project_dir(P).mkdir(parents=True, exist_ok=True)
    paths.project_manifest(P).write_text("project: myapp\n")
    return check_backup_freshness(paths).detail


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
    # A problem either way; the dangling link's names it as unreadable.
    Reader("scan_problem", lambda p: p.project_scan_state(P), {"scanned_at": ISO},
           lambda p: scan_state.scan_problem(p.project_scan_state(P), P, NOW),
           dangling=lambda o, _p: o[0] == "value" and "unreadable" in o[1]),
    Reader("read_scan_state", lambda p: p.project_scan_state(P), {"scanned_at": ISO},
           lambda p: scan_state.read_scan_state(p.project_scan_state(P))),
    Reader("pause", lambda p: p.project_paused_state(P), {"paused_at": ISO},
           lambda p: pause.read_paused_state(P, p)),
    Reader("release live.json", lambda p: p.project_releases(P) / "live.json", {"ref": "v1"},
           _live_ref),
    Reader("release previous.json", lambda p: p.project_releases(P) / "previous.json",
           {"ref": "v0", "data_snapshot": "", "replaced_at": ISO, "replaced_by": "v1"},
           _previous_release),
    Reader("suppressions", lambda p: project_suppressions_path(p, P), {"suppressions": []},
           lambda p: suppressions.load_suppressions(project_suppressions_path(p, P))),
    Reader("suppressions history",
           lambda p: suppressions.history_path_for(project_suppressions_path(p, P)),
           {"removed": []},
           lambda p: suppressions._load_history(
               suppressions.history_path_for(project_suppressions_path(p, P)))),
    Reader("breaker.read_held", breaker.breaker_path, {"held": {P: ["CVE-1"]}},
           breaker.read_held),
    Reader("breaker.alert_pending", breaker.breaker_path, {"held": {}, "alert_pending": True},
           breaker.alert_pending),
    # Specified: a cache it cannot read is an empty, stale catalog that
    # says why (scans report it), not a missing one.
    Reader("kev", lambda p: p.kev_catalog, {"cve_ids": ["CVE-1"], "fetched_at": ISO},
           lambda p: (kev.load_kev(p).cve_ids, kev.load_kev(p).unreadable is not None),
           dangling=lambda o, _p: o == ("value", (frozenset(), True))),
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
           lambda p: check_container_updates(p).detail,
           dangling=lambda o, _p: o[0] == "value" and o[1].startswith("unreadable state")),
    Reader("bind_sources", lambda p: p.project_bind_record(P),
           {"version": 2, "sources": {}, "control": {}}, lambda p: read_record(p.project_bind_record(P), redo="redeploy")),
    Reader("notify unconfigured", lambda p: p.alerts_unconfigured_state, {"logged_at": ISO},
           lambda p: _unconfigured_logged_recently(p, NOW),
           dangling=lambda o, p: _logged_unreadable(o, p, False)),
    # Deliberately quiet: any record it cannot use means "alert again", and
    # the refused start it throttles is logged and alerted on its own.
    Reader("start_alerts", lambda p: p.state / "start-refused" / f"{P}.json",
           {start_alerts.hashlib.sha256(b"r").hexdigest()[:16]: ISO},
           lambda p: start_alerts.alerted_recently(p, P, "r", NOW),
           dangling=lambda o, _p: o == ("value", False)),
    Reader("project_alerts", lambda p: alert_state(p, P, "production-down"), {"key": {"k": 1}},
           _alerted, dangling=lambda o, p: _logged_unreadable(o, p, True)),
    Reader("backup evidence", lambda p: p.project_backup_state(P),
           {"snapshot": "myapp-s.tar.gz.age", "snapshot_at": ISO},
           lambda p: project_evidence(p, P)),
    Reader("backup sync evidence", lambda p: p.backup_sync_state, {"synced_at": ISO},
           sync_evidence),
    Reader("health backup_freshness", lambda p: p.project_backup_state(P),
           {"snapshot": "myapp-s.tar.gz.age", "snapshot_at": ISO}, _backup_freshness,
           dangling=lambda o, _p: o[0] == "value" and "Cannot read state file" in o[1]),
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


def test_a_dangling_link_at_the_name_is_not_read_as_no_record(paths, tmp_path, reader) -> None:
    link = reader.path(paths)
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(tmp_path / "gone.json")
    outcome = _outcome(lambda: reader.read(paths))
    assert reader.dangling(outcome, paths), outcome


# Readers whose records are long to build: only the dangling link is
# checked here, and each must refuse it.
DANGLING_ONLY: list[tuple[str, Callable[[BoxPaths], Path], Callable[[BoxPaths], Any]]] = [
    ("install.json", lambda p: release_txn.txn_path(p, P),
     lambda p: release_txn.load_txn(p, P)),
    ("legacy-stages.json", lambda p: p.state / "legacy-stages.json", unresolved_stage._records),
    ("slot meta.json", lambda p: staged_release.slot_dir(p, P) / "meta.json",
     lambda p: staged_release.load_slot(p, P)),
    ("data dirs record", lambda p: data_dirs.record_path(p.project_dir(P)),
     lambda p: data_dirs._load_record(p.project_dir(P))),
    ("users record", lambda p: p.project_users_record(P), lambda p: run_as.read_users(p, P)),
    ("user drift", lambda p: p.project_user_drift(P), lambda p: user_drift.held_back(p, P)),
    ("upgrade probation", lambda p: p.probation, upgrade_state.read_probation),
    ("bind record control", lambda p: p.project_bind_record(P),
     lambda p: bind_sources.control_file_unchanged(p.project_dir(P), p.project_bind_record(P),
                                                   "compose.yml")),
]


@pytest.mark.parametrize("path, read", [(path, read) for _n, path, read in DANGLING_ONLY],
                         ids=[n for n, *_ in DANGLING_ONLY])
def test_a_dangling_link_is_refused(paths, tmp_path, path, read) -> None:
    link = path(paths)
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(tmp_path / "gone.json")
    assert _outcome(lambda: read(paths))[0] == "raised"


# Whether a project is in a state is whether there is anything at its
# record's name: a link there, dangling or not, is a record (reading it
# then refuses), never "not paused" or "never deployed".
PRESENCE: list[tuple[str, Callable[[BoxPaths], Path], Callable[[BoxPaths], Any], Any]] = [
    ("is_paused", lambda p: p.project_paused_state(P), lambda p: pause.is_paused(P, p), True),
    ("is_quarantined", lambda p: p.project_quarantine_state(P),
     lambda p: quarantine.is_quarantined(P, p), True),
    ("unfinished_removals", lambda p: p.project_deploy_state(P),
     lambda p: unfinished_removals({P}, p), [P]),
]


@pytest.mark.parametrize("path, probe, present", [row[1:] for row in PRESENCE],
                         ids=[row[0] for row in PRESENCE])
def test_a_dangling_link_counts_as_a_record(paths, tmp_path, path, probe, present) -> None:
    link = path(paths)
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(tmp_path / "gone.json")
    assert probe(paths) == present


def test_a_dangling_users_record_refuses_starting_old_containers(paths, tmp_path) -> None:
    """The users-record check of a `docker start` runs when anything is at
    the record's name: a dangling link must not skip it."""
    from boxmunge.compose_guard import ComposeRefused, check_containers_start
    paths.project_dir(P).mkdir(parents=True)
    paths.project_users_record(P).symlink_to(tmp_path / "gone.json")
    with patch("boxmunge.docker_containers.container_bind_sources", return_value=[]), \
            patch("boxmunge.compose_guard.bind_sources.read_record",
                  return_value={"sources": {}, "control": {}}), \
            patch("boxmunge.docker_containers.project_containers", return_value=[]), \
            patch("boxmunge.docker_containers.container_users", return_value={}), \
            patch("boxmunge.notify.send_notification", return_value=True):
        with pytest.raises(ComposeRefused, match="users record"):
            check_containers_start(paths, P, [f"{P}-web-1"], component="stage")


def test_only_nothing_at_the_name_reads_as_none(tmp_path) -> None:
    assert fs_nofollow.read_text_nofollow_or_none(tmp_path / "absent") is None
    assert fs_nofollow.read_text_nofollow_or_none(tmp_path / "no-dir" / "absent") is None
    (tmp_path / "here").write_text("x")
    assert fs_nofollow.read_text_nofollow_or_none(tmp_path / "here") == "x"
    (tmp_path / "dangling").symlink_to(tmp_path / "gone")
    with pytest.raises(OSError, match="symlink"):
        fs_nofollow.read_text_nofollow_or_none(tmp_path / "dangling")


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
