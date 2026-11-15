# SPDX-License-Identifier: Apache-2.0
"""`boxmunge security kev-watch`: notice a newly listed known-exploited CVE
within the timer's interval, not at the nightly scan.

Each tick refreshes every source, then diffs the union of listed CVEs
against the set the last tick saw (cve.kev_watch_state). A project whose
stored findings (state/scans) contain a newly listed CVE is rescanned
through the one judging path, so it is judged, quarantined and alerted
exactly as the nightly scan would. Nothing else is scanned.

The record is written last: a crash re-processes the diff. A CVE whose
affected project could not be rescanned (lock held, scan failed, or the
circuit breaker failed) stays out of the written set, so the next tick
retries it. A project whose rescan failed is retried until a complete scan
newer than the watch's last attempt (the nightly one) has covered it, and
its failure is alerted once a day. A project whose result could not be
recorded (``run.unrecorded``) counts as processed: it was judged and
enforced, only the record failed, and that has its own alert.

Every tick then runs the urgent autofix queue (commands.autofix_urgent),
still under the fleet lock, whatever the diff found: a patch queued by this
tick's rescans, or by a single-project scan since the last tick.

The tick holds the fleet lock (cve.fleet_lock) for its whole run and skips
itself when the nightly scan has it. The watch's refresh neither sends the
degraded-catalog alert nor counts passed-over runs (security_kev): both stay
nightly. The refresh runs before the first-run check, so a first tick also
caches fresh catalogs.
"""
from __future__ import annotations

import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from boxmunge.commands.autofix_urgent import run_urgent_queue
from boxmunge.commands.security_actions import BREAKER_PROBLEM, scan_projects
from boxmunge.commands.security_kev import refresh_kev_and_alert
from boxmunge.cve.exploited import load_exploited
from boxmunge.cve.fleet_lock import FleetLockBusy, fleet_lock
from boxmunge.cve.kev_watch_state import Failing, WatchState, read_watch, write_watch
from boxmunge.cve.scan_state import decisions_from_scan_state, read_scan_state
from boxmunge.cve.scanner import TrivyNotInstalledError
from boxmunge.lifecycle import migration_refusal
from boxmunge.log import log_operation, log_warning
from boxmunge.paths import BoxPaths
from boxmunge.project_inventory import project_dir_names
from boxmunge.state import StateError

_SHAPE_ERRORS = (StateError, ValueError, KeyError, TypeError, AttributeError)


@dataclass(frozen=True)
class WatchResult:
    new_cves: frozenset[str] = frozenset()
    rescanned: tuple[str, ...] = ()
    # Held by another operation: skipped, retried next tick.
    busy: tuple[str, ...] = ()
    # Rescan failed or incomplete: retried until a nightly scan covers it; the run fails.
    failed: tuple[str, ...] = ()
    # The nightly scan held the fleet lock: the whole tick was skipped.
    skipped: bool = False


def _stored_cves(paths: BoxPaths, project: str) -> frozenset[str] | None:
    """The CVE ids in the project's stored findings; None (warned about,
    naming the project) when there are no usable stored findings: the
    nightly scan covers it."""
    try:
        state = read_scan_state(paths.project_scan_state(project))
        if state is None:
            log_warning("cve-scan", f"kev-watch: {project} skipped, it has no stored scan; "
                        f"the nightly scan will cover it", paths, project=project)
            return None
        decisions = decisions_from_scan_state(state, project_name=project)
    except _SHAPE_ERRORS as e:
        log_warning("cve-scan", f"kev-watch: {project} skipped, its stored scan is unusable "
                    f"({e!r}); the nightly scan will cover it", paths, project=project)
        return None
    return frozenset(f.finding.cve_id for d in decisions for f in d.findings)


def _covered_since(paths: BoxPaths, project: str, attempted_at: datetime) -> bool:
    """Whether a complete scan newer than the watch's last attempt has run."""
    try:
        state = read_scan_state(paths.project_scan_state(project))
        return (state is not None and not state.get("unscanned")
                and datetime.fromisoformat(state["scanned_at"]) > attempted_at)
    except _SHAPE_ERRORS as e:
        log_warning("cve-scan", f"kev-watch: cannot tell whether {project} was rescanned "
                    f"({e!r})", paths, project=project)
        return False


def run_kev_watch(paths: BoxPaths, now: datetime) -> WatchResult:
    """One tick. Raises StateError (an unusable record) or
    TrivyNotInstalledError; either leaves the record unwritten."""
    try:
        with fleet_lock(paths):
            return _tick(paths, now)
    except FleetLockBusy as e:
        log_operation("cve-scan", f"kev-watch: tick skipped, {e}", paths)
        return WatchResult(skipped=True)


def _tick(paths: BoxPaths, now: datetime) -> WatchResult:
    """The tick, then the urgent patches any scan queued (autofix_urgent):
    this one's rescans, or a single-project scan since the last tick."""
    try:
        result = _watch(paths, now)
    except Exception:
        run_urgent_queue(paths, now)
        raise
    run_urgent_queue(paths, now)
    return result


def _watch(paths: BoxPaths, now: datetime) -> WatchResult:
    started = time.monotonic()
    kev = refresh_kev_and_alert(paths, now, nightly=False)
    listed = frozenset(load_exploited(paths, now.date(), cisa=kev).by_cve)
    previous = read_watch(paths)
    if previous is None:
        write_watch(paths, WatchState(now, listed))
        log_operation("cve-scan", f"kev-watch: first run, recorded {len(listed)} listed CVEs "
                      f"and rescanned nothing (the nightly scan judged against what existed)",
                      paths)
        return WatchResult()

    new = listed - previous.cve_ids
    hits: dict[str, frozenset[str]] = {}
    for project in project_dir_names(paths) if new else ():
        stored = _stored_cves(paths, project)
        if stored and stored & new:
            hits[project] = stored & new

    covered = {p for p in hits if p in previous.failing
               and _covered_since(paths, p, previous.failing[p].attempted_at)}
    for project in sorted(covered):
        log_operation("cve-scan", f"kev-watch: {project} was covered by a later complete scan; "
                      f"no more retries", paths, project=project)
    targets = sorted(set(hits) - covered)
    today = now.date()
    quiet = frozenset(p for p, f in previous.failing.items() if f.alerted_on == today)

    busy: set[str] = set()
    failed: set[str] = set()
    breaker = False
    if targets:
        run = scan_projects(paths, targets, kev=kev, quiet=quiet)
        busy = set(run.skipped_locked) & set(targets)
        breaker = BREAKER_PROBLEM in run.problems
        # A breaker failure applied no quarantine for any project of the run.
        failed = set(targets) if breaker else set(run.problems) & set(targets)

    attempted_at = now + timedelta(seconds=time.monotonic() - started)
    failing = {p: f for p, f in previous.failing.items() if p in hits and p not in covered}
    for project in targets:
        if project not in busy:
            failing.pop(project, None)
    for project in failed | ({BREAKER_PROBLEM} if breaker else set()):
        failing[project] = Failing(attempted_at, today)

    unprocessed = busy | failed
    for project in sorted(unprocessed):
        log_warning("cve-scan", f"kev-watch: {project} not rescanned cleanly; retried next "
                    f"tick", paths, project=project)
    held_back = frozenset().union(*(hits[p] for p in unprocessed))
    write_watch(paths, WatchState(now, previous.cve_ids | (listed - held_back), failing))
    if new:
        log_operation("cve-scan", f"kev-watch: {len(new)} newly listed, rescanned "
                      f"{targets or 'no project'}", paths)
    return WatchResult(new, tuple(t for t in targets if t not in unprocessed),
                       tuple(sorted(busy)), tuple(sorted(failed)))


def cmd_kev_watch(args: list[str], paths: BoxPaths) -> int:
    """boxmunge security kev-watch. Exit 1 when a project could not be
    rescanned or the watch cannot run."""
    if args:
        print("ERROR: security kev-watch takes no arguments", file=sys.stderr)
        return 2
    refusal = migration_refusal("security kev-watch", paths)
    if refusal:
        print(f"ERROR: {refusal}", file=sys.stderr)
        return 1
    try:
        result = run_kev_watch(paths, datetime.now(timezone.utc))
    except (StateError, TrivyNotInstalledError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    if result.skipped:
        print("Skipped: the nightly scan holds the fleet lock; the next tick covers it.")
        return 0
    print(f"{len(result.new_cves)} newly listed; rescanned: {', '.join(result.rescanned) or 'none'}")
    if result.busy:
        print(f"Busy, retried next tick: {', '.join(result.busy)}")
    if result.failed:
        print(f"Rescan failed, retried next tick: {', '.join(result.failed)}", file=sys.stderr)
    return 1 if result.failed else 0
