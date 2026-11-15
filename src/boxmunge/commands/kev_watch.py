# SPDX-License-Identifier: Apache-2.0
"""`boxmunge security kev-watch`: notice a newly listed known-exploited CVE
within the timer's interval, not at the nightly scan.

Each tick refreshes every source, then diffs the union of listed CVEs
against the set the last tick saw (cve.kev_watch_state). A project whose
stored findings (state/scans) contain a newly listed CVE is rescanned
through the one judging path, so it is judged, quarantined and alerted
exactly as the nightly scan would. Nothing else is scanned.

The record is written last: a crash re-processes the diff. A CVE whose
affected project could not be rescanned (lock held, scan failed) stays out
of the written set, so the next tick retries it.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import datetime, timezone

from boxmunge.commands.security_actions import scan_projects
from boxmunge.commands.security_kev import refresh_kev_and_alert
from boxmunge.cve.exploited import load_exploited
from boxmunge.cve.kev_watch_state import WatchState, read_watch, write_watch
from boxmunge.cve.scan_state import read_scan_state
from boxmunge.cve.scanner import TrivyNotInstalledError
from boxmunge.lifecycle import migration_refusal
from boxmunge.log import log_operation, log_warning
from boxmunge.paths import BoxPaths
from boxmunge.project_inventory import project_dir_names
from boxmunge.state import StateError


@dataclass(frozen=True)
class WatchResult:
    new_cves: frozenset[str]
    rescanned: tuple[str, ...]
    # Held by another operation: skipped, retried next tick.
    busy: tuple[str, ...]
    # Rescan failed or incomplete: retried next tick, and the run fails.
    failed: tuple[str, ...]


def _stored_cves(paths: BoxPaths, project: str) -> frozenset[str] | None:
    """The CVE ids in the project's stored findings; None when there are no
    readable stored findings (the nightly scan covers it)."""
    try:
        state = read_scan_state(paths.project_scan_state(project))
    except StateError as e:
        log_warning("cve-scan", f"kev-watch: {project} skipped, its stored scan is "
                    f"unreadable ({e}); the nightly scan will cover it", paths, project=project)
        return None
    if state is None:
        log_warning("cve-scan", f"kev-watch: {project} skipped, it has no stored scan; "
                    f"the nightly scan will cover it", paths, project=project)
        return None
    return frozenset(
        f["cve_id"] for d in state.get("decisions") or [] for f in d.get("findings") or [])


def run_kev_watch(paths: BoxPaths, now: datetime) -> WatchResult:
    """One tick. Raises StateError (an unusable record) or
    TrivyNotInstalledError; either leaves the record unwritten."""
    kev = refresh_kev_and_alert(paths, now)
    listed = frozenset(load_exploited(paths, now.date(), cisa=kev).by_cve)
    previous = read_watch(paths)
    if previous is None:
        write_watch(paths, WatchState(now, listed))
        log_operation("cve-scan", f"kev-watch: first run, recorded {len(listed)} listed CVEs "
                      f"and rescanned nothing (the nightly scan judged against what existed)",
                      paths)
        return WatchResult(frozenset(), (), (), ())

    new = listed - previous.cve_ids
    hits: dict[str, frozenset[str]] = {}
    for project in project_dir_names(paths):
        stored = _stored_cves(paths, project) if new else None
        if stored and stored & new:
            hits[project] = stored & new
    run = scan_projects(paths, sorted(hits), kev=kev) if hits else None

    unprocessed: set[str] = set()
    if run is not None:
        unprocessed = {*run.skipped_locked, *run.problems}
        for project in sorted(unprocessed):
            log_warning("cve-scan", f"kev-watch: {project} not rescanned cleanly; "
                        f"retried next tick", paths, project=project)
    held_back = frozenset().union(*(hits[p] for p in unprocessed)) if unprocessed else frozenset()
    write_watch(paths, WatchState(now, previous.cve_ids | (listed - held_back)))
    if new:
        log_operation("cve-scan", f"kev-watch: {len(new)} newly listed, rescanned "
                      f"{sorted(hits) or 'no project'}", paths)
    return WatchResult(new, tuple(sorted(set(hits) - unprocessed)),
                       tuple(sorted(run.skipped_locked)) if run else (),
                       tuple(sorted(run.problems)) if run else ())


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
    print(f"{len(result.new_cves)} newly listed; rescanned: {', '.join(result.rescanned) or 'none'}")
    if result.busy:
        print(f"Busy, retried next tick: {', '.join(result.busy)}")
    if result.failed:
        print(f"Rescan failed, retried next tick: {', '.join(result.failed)}", file=sys.stderr)
    return 1 if result.failed else 0
