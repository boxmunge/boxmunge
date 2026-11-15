# SPDX-License-Identifier: Apache-2.0
"""Health checks: container hardening profiles and CVE scan freshness.

`security-profiles` surfaces any service whose effective security profile
is `off`, so the operator sees the un-hardened surface during routine
`boxmunge health` runs (not only at deploy time).

`cve-scan` warns when a project has not been scanned recently or its last
scan did not cover every image: a project the nightly scan keeps missing
is not protected by quarantine (audit B-11).

`cve-hardening` warns about findings the 0.12 hardening penalty lifts to
the posture's gate, on the postures where that can decide downtime.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from boxmunge.commands.health_cmd import HealthCheck
from boxmunge.config import ConfigError
from boxmunge.cve.exploited import ExploitedSource, load_exploited
from boxmunge.cve.kev_config import kev_config
from boxmunge.cve.kev_watch_state import read_watch
from boxmunge.cve.policy import PolicyError, parse_posture, penalty_can_decide_downtime
from boxmunge.cve.scan_state import SCAN_MAX_AGE, read_scan_state, scan_problem
from boxmunge.manifest import ManifestError, load_manifest
from boxmunge.project_inventory import Inventory, classify, damaged_among, damaged_detail
from boxmunge.project_registry import deployed_among, read_registry
from boxmunge.state import StateError

from boxmunge.security_overlay import (
    services_with_off_profile,
    services_with_overrides,
)

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def check_security_profiles(paths: BoxPaths) -> HealthCheck:
    """Warn when any deployed project has a service running profile: off.

    Returns ok (silent success) when every service across every project
    resolves to the default profile. When any service is opted out, returns
    warn with a detail line listing each `project/service: reason`.
    """
    if not paths.projects.exists():
        return HealthCheck(
            name="security-profiles", status="ok", detail="no projects deployed",
        )

    off_entries: list[str] = []
    override_entries: list[str] = []
    damaged: list[str] = []
    for project_dir in sorted(paths.projects.iterdir()):
        if not project_dir.is_dir():
            continue
        manifest_path = project_dir / "manifest.yml"
        standing = classify(project_dir.name, paths)
        if standing is Inventory.DAMAGED:
            damaged.append(f"{project_dir.name}: {damaged_detail(project_dir.name)}")
            continue
        if standing is Inventory.AWAITING:
            continue
        try:
            manifest = load_manifest(manifest_path)
        except ManifestError:
            continue

        project_name = manifest.get("project", project_dir.name)
        for svc_name, reason in services_with_off_profile(manifest):
            reason_text = reason or "(no reason recorded)"
            off_entries.append(f"{project_name}/{svc_name}: {reason_text}")
        for svc_name, diffs in services_with_overrides(manifest):
            override_entries.append(f"{project_name}/{svc_name} ({', '.join(diffs)})")

    # `off` services are warn-level. Overrides are appended to detail
    # for visibility but do not escalate status.
    if damaged and not off_entries:
        return HealthCheck(name="security-profiles", status="warn",
                           detail="not checked -- " + "; ".join(damaged))
    if off_entries:
        detail = "SECURITY OFF -- " + "; ".join(off_entries)
        if damaged:
            detail += " | not checked: " + "; ".join(damaged)
        if override_entries:
            detail += " | overrides: " + "; ".join(override_entries)
        return HealthCheck(
            name="security-profiles", status="warn", detail=detail,
        )
    if override_entries:
        return HealthCheck(
            name="security-profiles", status="ok",
            detail="all services on default profile (with overrides: "
                   + "; ".join(override_entries) + ")",
        )
    return HealthCheck(
        name="security-profiles", status="ok",
        detail="all services on default profile",
    )


def check_cve_scan_freshness(paths: BoxPaths, *, now: datetime | None = None) -> HealthCheck:
    """Warn when any deployed project's CVE scan is stale or incomplete."""
    now = now or datetime.now(timezone.utc)
    registry = read_registry(paths)
    projects = deployed_among(registry.names, paths)
    if not projects and not registry.problems:
        return HealthCheck(name="cve-scan", status="ok", detail="no projects deployed")
    # A bad registry line may be a project the scan cannot see.
    problems = [f"not a project name, so never scanned: {p}" for p in registry.problems]
    problems += [f"{n}: {damaged_detail(n)}" for n in damaged_among(projects, paths)]
    problems += [p for p in (scan_problem(paths.project_scan_state(name), name, now) for name in projects) if p]
    if problems:
        return HealthCheck(
            name="cve-scan", status="warn",
            detail="unprotected by CVE quarantine until scanned -- " + "; ".join(problems),
        )
    return HealthCheck(
        name="cve-scan", status="ok",
        detail=f"all {len(projects)} deployed projects scanned within {int(SCAN_MAX_AGE.total_seconds() // 3600)}h",
    )


# The watch ticks every 30 minutes (RandomizedDelaySec up to 2 more): two
# missed ticks plus the delay is 75 minutes.
KEV_WATCH_MAX_AGE = timedelta(minutes=75)
KEV_WATCH_TIMER = Path("/etc/systemd/system/boxmunge-kev-watch.timer")


def _optional_sources(paths: BoxPaths) -> set[ExploitedSource]:
    """The optional known-exploited sources the operator has left on."""
    config = kev_config(paths)
    return ({ExploitedSource.EU} if config.enisa_enabled else set()) | (
        {ExploitedSource.VULNCHECK} if config.vulncheck_token else set())


def check_kev_watch_freshness(paths: BoxPaths, *, now: datetime | None = None) -> HealthCheck:
    """Warn when the KEV watch has stopped ticking, or an optional
    known-exploited source (the EU list, VulnCheck) is stale: that is the
    only operator-visible sign of a feed that keeps failing."""
    now = now or datetime.now(timezone.utc)
    problems: list[str] = []
    watch = None
    try:
        watch = read_watch(paths)
    except StateError as e:
        problems.append(str(e))
    if watch is not None:
        age = now - watch.seen_at
        if age > KEV_WATCH_MAX_AGE:
            problems.append(f"the KEV watch last ran {int(age.total_seconds() // 60)} minutes "
                            f"ago (it runs every 30): new known-exploited CVEs wait for the "
                            f"nightly scan; check `systemctl status boxmunge-kev-watch.timer`")
    elif not problems and os.path.lexists(KEV_WATCH_TIMER) and (
            now - datetime.fromtimestamp(KEV_WATCH_TIMER.lstat().st_mtime, timezone.utc)
            > KEV_WATCH_MAX_AGE):
        problems.append("the KEV watch timer is installed but the watch has never run; "
                        "check `systemctl status boxmunge-kev-watch.service`")
    try:
        stale = load_exploited(paths, now.date()).stale
        optional = _optional_sources(paths)
    except (StateError, ConfigError) as e:
        problems.append(f"known-exploited sources unreadable: {e}")
    else:
        problems += [f"{src.value} not usable: {why}" for src, why in sorted(stale.items())
                     if src in optional]
    if problems:
        return HealthCheck(name="kev-watch", status="warn", detail="; ".join(problems))
    return HealthCheck(name="kev-watch", status="ok",
                       detail="the KEV watch is ticking and its sources are fresh")


def _penalty_decides_downtime(paths: BoxPaths, name: str) -> bool:
    """Whether the project's posture lets the hardening penalty decide
    downtime (strict, paranoid). Raises ManifestError / PolicyError when the
    posture cannot be read."""
    sec = load_manifest(paths.project_manifest(name)).get("security") or {}
    return penalty_can_decide_downtime(parse_posture(sec.get("posture")))


def check_cve_hardening_upcoming(paths: BoxPaths) -> HealthCheck:
    """Warn when a project has findings that meet its gate from 0.12, not now.

    The hardening penalty counts a compose-only service without
    `read_only: true` (and a manifest `cap_add` / `no_new_privileges: false`);
    0.11 only warns. These findings are not quarantined, so they are not
    safe either: the fix is named in `boxmunge security <project>`.

    Only under strict and paranoid can the penalty decide downtime: paranoid
    quarantines at its gate; strict alerts and patches there, and a fix not
    deployed in time quarantines. A project on balanced
    or relaxed is never warned, even when a scan recorded before it moved
    there (or before 0.11.2, when balanced still did) carries the flag.
    """
    registry = read_registry(paths)
    flagged: list[str] = []
    for name in deployed_among(registry.names, paths):
        try:
            if not _penalty_decides_downtime(paths, name):
                continue
        except (ManifestError, PolicyError) as e:
            flagged.append(f"{name}: posture unreadable ({e})")
            continue
        try:
            state = read_scan_state(paths.project_scan_state(name))
        except StateError as e:
            flagged.append(f"{name}: scan state unreadable ({e})")
            continue
        n = len({
            (f.get("cve_id"), f.get("package"))
            for d in (state or {}).get("decisions") or []
            for f in d.get("findings") or []
            if f.get("hardening_would_quarantine") is True
        })
        if n:
            flagged.append(f"{name}: {n} finding(s)")
    if flagged:
        return HealthCheck(
            name="cve-hardening", status="warn",
            detail="from 0.12 the stricter hardening penalty lifts these findings to the "
                   "gate under posture strict or paranoid (paranoid quarantines them; "
                   "strict alerts and patches them, and a fix not deployed can start the "
                   "fix deadline; nothing is acted on now); add `read_only: true` in "
                   "compose.yml, declare the "
                   "service in the manifest, or accept the risk (suppress the CVE after "
                   "review, or choose `security.posture: balanced`, which quarantines only "
                   "on actively exploited CVEs); see `boxmunge security <project>` -- "
                   + "; ".join(flagged),
        )
    return HealthCheck(name="cve-hardening", status="ok",
                       detail="no finding is waiting on the 0.12 hardening rule")
