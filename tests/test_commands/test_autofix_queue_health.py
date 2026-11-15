# SPDX-License-Identifier: Apache-2.0
"""What keeps the urgent queue honest: a stuck entry stops holding its
quarantine back and is alerted, a unit that will not start is alerted, a
stored scan older than the entry keeps it queued, a rescan merges into the
entry, and a patch that fails every time is not retried (or alerted) every
run while nothing it depends on changes (cve.autofix_failed)."""
from __future__ import annotations

import json
from dataclasses import replace
from datetime import timedelta

from boxmunge.commands import autofix_queue_cmd
from boxmunge.cve.autofix_failed import remembered
from boxmunge.cve.autofix_policy import AUTOFIX_QUEUE_MAX_WAIT
from boxmunge.cve.autofix_record import read_autofixing, read_queue_entry, write_queue_entry
from boxmunge.cve.autofix_run import AutofixOutcome
from boxmunge.cve.quarantine import is_quarantined
from boxmunge.fileutil import project_lock
from boxmunge.health_checks.autofix import check_autofix_queue
from boxmunge.state import write_state
from tests.test_commands import test_autofix_nightly as nightly
from tests.test_commands.test_autofix_urgent import CVE, Systemctl, _box, _now

FAILED = AutofixOutcome(False, "build", "the mirror is unreachable", ())


def _age(box, hours: float) -> None:
    """The queued entry was found (and written) `hours` ago."""
    entry = read_queue_entry(box.paths, "demo")
    when = _now() - timedelta(hours=hours)
    write_queue_entry(box.paths, "demo", replace(entry, detected_at=when, queued_at=when))


# ---------- a stuck entry ----------


def test_a_stuck_entry_stops_holding_the_quarantine_back(tmp_path, monkeypatch) -> None:
    """Balanced, full KEV below 9: up while patched; once the patch has not
    started for 2h, the scan quarantines it (table B) and alerts once a day."""
    box = _box(tmp_path, monkeypatch, "balanced", cvss=7.5)
    box.scan()
    assert not is_quarantined("demo", box.paths)
    _age(box, 1)
    box.scan()
    assert not is_quarantined("demo", box.paths) and box.sent("could not start") == []
    _age(box, 3)
    box.scan()
    assert is_quarantined("demo", box.paths)
    assert read_queue_entry(box.paths, "demo").downtime is True   # it now runs dark
    assert read_autofixing(box.paths, "demo").downtime is True
    [stuck] = box.sent("could not start")
    assert stuck[2] == 1 and "could not start for 2h" in stuck[1]
    box.scan()
    assert len(box.sent("could not start")) == 1   # once a day
    [outcome] = box.run()   # the patch still runs, and lifts the quarantine
    assert outcome.ok and box.runner.dark == [True] and not is_quarantined("demo", box.paths)


def test_a_stuck_entry_whose_policy_keeps_the_site_up_only_alerts(tmp_path,
                                                                 monkeypatch) -> None:
    box = _box(tmp_path, monkeypatch, "relaxed")
    box.scan()
    _age(box, 3)
    box.scan()
    assert not is_quarantined("demo", box.paths)
    assert len(box.sent("could not start")) == 1


def test_the_runner_alerts_a_stuck_entry_it_cannot_lock(tmp_path, monkeypatch) -> None:
    box = _box(tmp_path, monkeypatch, "relaxed")
    box.scan()
    _age(box, 3)
    with project_lock("demo", box.paths):
        assert box.run() == []
    [stuck] = box.sent("could not start")
    assert "another operation has held the project" in stuck[1]


def test_health_warns_for_an_entry_older_than_the_limit(tmp_path, monkeypatch) -> None:
    box = _box(tmp_path, monkeypatch, "relaxed")
    assert check_autofix_queue(box.paths).status == "ok"
    box.scan()
    assert check_autofix_queue(box.paths).status == "ok"
    _age(box, AUTOFIX_QUEUE_MAX_WAIT.total_seconds() / 3600 + 0.1)
    check = check_autofix_queue(box.paths)
    assert (check.name, check.status) == ("autofix-queue", "warn")
    assert "demo" in check.detail and CVE in check.detail


def test_health_warns_for_an_unreadable_entry(tmp_path, monkeypatch) -> None:
    box = _box(tmp_path, monkeypatch, "relaxed")
    box.scan()
    box.paths.project_autofix_queue("demo").write_text("{not json")
    assert check_autofix_queue(box.paths).status == "warn"


def test_a_unit_that_will_not_start_is_alerted_once_a_day(tmp_path, monkeypatch) -> None:
    box = _box(tmp_path, monkeypatch, "relaxed")
    box.scan()
    Systemctl(monkeypatch, returncode=5)
    autofix_queue_cmd.start_autofix_unit(box.paths)
    autofix_queue_cmd.start_autofix_unit(box.paths)
    [alert] = box.sent("Urgent autofix could not start")
    assert alert[2] == 1 and "boxmunge-autofix.service could not be started" in alert[1]


# ---------- the entry against the stored scan ----------


def test_a_stored_scan_older_than_the_entry_keeps_it_queued(tmp_path, monkeypatch) -> None:
    """The scan that queued the patch could not record its results: the
    runner must not read the findings as gone and drop the patch."""
    box = _box(tmp_path, monkeypatch, "balanced", cvss=7.5)
    box.scan()
    path = box.paths.project_scan_state("demo")
    state = json.loads(path.read_text())
    state["scanned_at"] = (_now() - timedelta(hours=1)).isoformat()
    state["decisions"] = []
    write_state(path, state)
    assert box.run() == [] and box.runner.calls == []
    assert read_queue_entry(box.paths, "demo") is not None
    [problem] = box.sent("could not run")
    assert "older than its queued patch" in problem[1]


def test_a_rescan_with_a_new_finding_merges_into_the_entry(tmp_path, monkeypatch) -> None:
    from tests.test_commands.cve_helpers import finding
    box = _box(tmp_path, monkeypatch, "relaxed")
    box.scan()
    first = read_queue_entry(box.paths, "demo")
    box.found = [*box.found, replace(finding("CVE-2026-0002", fix="2", pkg="zlib"),
                                     cvss_score=9.8)]
    import boxmunge.commands.security_scan_core as core
    from boxmunge.cve.exploited import ExploitedIndex
    monkeypatch.setattr(core, "load_exploited", lambda p, today, cisa=None: ExploitedIndex(
        {CVE: box.listed, "CVE-2026-0002": box.listed}, {}))
    box.scan()
    entry = read_queue_entry(box.paths, "demo")
    assert entry.detected_at == first.detected_at and entry.queued_at > first.queued_at
    assert set(first.findings) < set(entry.findings)
    assert entry.cves == (CVE, "CVE-2026-0002")


# ---------- a patch that fails every time ----------


def test_a_failed_urgent_patch_is_not_queued_again_until_something_changes(
        tmp_path, monkeypatch) -> None:
    box = _box(tmp_path, monkeypatch, "balanced", cvss=7.5)
    box.scan()
    box.runner.outcome = FAILED
    box.run()
    assert is_quarantined("demo", box.paths)          # table B
    assert len(box.sent("Autofix FAILED")) == 1
    assert remembered(box.paths, "demo", "urgent").failed_step == "build"
    for _ in range(2):
        box.scan()
        assert read_queue_entry(box.paths, "demo") is None
        assert box.run() == []
    assert len(box.runner.calls) == 1 and len(box.sent("Autofix FAILED")) == 1
    assert len(box.sent("patching")) == 1 and is_quarantined("demo", box.paths)
    # A new fixed version is a change: tried again.
    box.found = [replace(f, fixed_version="3") for f in box.found]
    box.scan()
    assert read_queue_entry(box.paths, "demo") is not None
    assert remembered(box.paths, "demo", "urgent") is None
    box.runner.outcome = None
    [outcome] = box.run()
    assert outcome.ok and remembered(box.paths, "demo", "urgent") is None


def test_nothing_to_patch_forgets_a_failure(tmp_path, monkeypatch) -> None:
    box = _box(tmp_path, monkeypatch, "relaxed")
    box.scan()
    box.runner.outcome = FAILED
    box.run()
    assert remembered(box.paths, "demo", "urgent") is not None
    box.found = [replace(f, fixed_version="3") for f in box.found]
    box.scan()
    box.runner.outcome = AutofixOutcome(False, "scan", "gone", (), nothing_to_patch=True)
    box.run()
    assert remembered(box.paths, "demo", "urgent") is None


def test_a_failed_nightly_patch_is_not_retried_and_the_digest_says_so(tmp_path,
                                                                      monkeypatch) -> None:
    box = nightly.Box(tmp_path, monkeypatch)
    box.scan()
    box.runner.outcome = FAILED
    box.update()
    assert len(box.runner.calls) == 1
    box.pushover.clear()
    box.scan()
    box.update()
    assert len(box.runner.calls) == 1   # not attempted again
    [(_title, body, priority)] = box.digests()
    assert priority == -1
    assert f"still unpatched since {_now().date().isoformat()}: demo: build: " \
           "the mirror is unreachable" in body
    # A new base image is a change: tried again.
    box.found = [replace(f, fixed_version="3") for f in box.found]
    box.scan()
    box.runner.outcome = None
    box.update()
    assert len(box.runner.calls) == 2 and remembered(box.paths, "demo", "nightly") is None


def test_the_nightly_digest_lists_an_urgent_patch_still_unpatched(tmp_path,
                                                                  monkeypatch) -> None:
    box = _box(tmp_path, monkeypatch, "relaxed")
    box.scan()
    box.runner.outcome = FAILED
    box.run()
    from boxmunge.commands import autofix_nightly
    attempts = autofix_nightly.urgent_unpatched(box.paths, only=None)
    [line] = attempts
    assert autofix_nightly.describe(line).startswith(
        f"still unpatched since {_now().date().isoformat()}: demo: build: ")
