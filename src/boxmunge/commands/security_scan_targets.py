# SPDX-License-Identifier: Apache-2.0
"""What a `security scan` run covers, and its housekeeping.

Split from security_actions (fleet orchestration): resolving the projects
to scan, the registered names left without a directory, the per-project
summary line, and retiring an older release's migration grace files.
"""
from __future__ import annotations

import sys

from boxmunge import docker_containers
from boxmunge.cve.policy import Disposition, ProjectDecision
from boxmunge.docker_run import DockerError
from boxmunge.log import log_operation, log_warning
from boxmunge.paths import BoxPaths
from boxmunge.project_registry import (
    deployed_among, forget_advice, is_registered, missing_among, read_registry,
    unfinished_removals,
)


# The v0.6.0 migration grace window's marker and its lock. Every box's
# window closed in May 2026 and nothing reads them any more; the scan
# removes what an older release left behind.
_RETIRED_GRACE_FILES = ("cve-grace.json", ".cve-grace.lock")


def retire_grace_marker(paths: BoxPaths) -> None:
    """Remove the retired grace marker and lock; say so once, when they go.

    A file that cannot be removed is warned about, not raised: it is inert,
    and the scan it would block is the box's CVE enforcement."""
    removed = []
    for name in _RETIRED_GRACE_FILES:
        path = paths.state / name
        try:
            path.unlink()
        except FileNotFoundError:
            continue
        except OSError as e:
            log_warning("cve-scan", f"could not remove the retired {path}: {e}; "
                        f"remove it by hand: sudo rm {path}", paths)
            continue
        removed.append(name)
    if removed:
        log_operation("cve-scan", f"removed the retired migration grace files: "
                      f"{', '.join(removed)}", paths)


def summarise_decisions(decisions: list[ProjectDecision]) -> str:
    """One-line counts of dispositions across all decisions."""
    counts: dict[str, int] = {}
    total = 0
    for d in decisions:
        for f in d.findings:
            total += 1
            counts[f.disposition.value] = counts.get(f.disposition.value, 0) + 1
    if total == 0:
        return "0 findings"
    parts = []
    for tag in (
        Disposition.QUARANTINE.value,
        Disposition.SUPPRESSED.value,
        Disposition.STILL_RUNNING_AT_RISK.value,
        Disposition.AWAITING_FIX.value,
        Disposition.INFORMATIONAL.value,
        Disposition.IGNORED_FIXED.value,
    ):
        c = counts.get(tag, 0)
        if c:
            parts.append(f"{c} {tag.replace('_', '-')}")
    return f"{total} findings ({', '.join(parts)})"


def parse_scan_targets(
    args: list[str], paths: BoxPaths,
) -> tuple[list[str], tuple[str, ...], list[str]] | int:
    """Resolve the projects to scan, any registry problems and the registered
    names with no project directory, or return a lookup exit code.

    A fleet scan scans every valid registered project and carries each bad
    registry line forward to be reported. Usage errors exit 2 from parse_args.
    """
    from boxmunge.commands.argv import parse_args, require_project_name
    parsed = parse_args("security", args, max_positional=1)
    if not parsed.positional:
        registry = read_registry(paths)
        return (deployed_among(registry.names, paths), registry.problems,
                missing_among(registry.names, paths))
    project = require_project_name("security", parsed.positional[0])
    if not is_registered(project, paths):
        print(f"ERROR: project '{project}' is not registered.", file=sys.stderr)
        return 1
    if unfinished_removals({project}, paths):
        print(f"ERROR: {forget_advice(project)}.", file=sys.stderr)
        return 1
    if missing_among({project}, paths):
        print(f"{project} is awaiting its first deploy: nothing to scan.")
        return 0
    return [project], (), []


def report_unfinished(paths: BoxPaths, missing: list[str]) -> None:
    """Say once per run which registered names are left behind by an
    unfinished removal (a name merely awaiting its first deploy is not
    mentioned). Not a scan failure: there is nothing to scan, and doctor and
    health keep reporting it until the entry is dropped."""
    unfinished = unfinished_removals(set(missing), paths)
    if not unfinished:
        return
    message = (f"registered but missing, so not scanned: {', '.join(unfinished)}. Drop "
               f"each entry as the supervisor: sudo boxmunge-server project-forget <name>")
    print(f"NOTE: {message}")
    log_warning("cve-scan", message, paths, detail={"missing": unfinished})


def orphaned(missing: list[str]) -> dict[str, list[str]]:
    """Registered names with no project directory whose containers exist (or
    cannot be ruled out): they run, unscanned and unmanaged, so they fail
    the run."""
    found: dict[str, list[str]] = {}
    for name in missing:
        try:
            names = [c.name for p in (name, f"{name}-staging")
                     for c in docker_containers.project_containers(p)]
        except DockerError as e:
            found[name] = [f"no project directory, and Docker could not be asked "
                           f"whether containers remain: {e}"]
            continue
        if names:
            found[name] = [f"no project directory, but containers still exist "
                           f"({', '.join(names)}) and are not scanned; remove them "
                           f"with project-delete {name}"]
    return found
