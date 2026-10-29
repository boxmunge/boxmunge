# SPDX-License-Identifier: Apache-2.0
"""Health checks: container hardening profiles and CVE scan freshness.

`security-profiles` surfaces any service whose effective security profile
is `off`, so the operator sees the un-hardened surface during routine
`boxmunge health` runs (not only at deploy time).

`cve-scan` warns when a project has not been scanned recently or its last
scan did not cover every image: a project the nightly scan keeps missing
is not protected by quarantine (audit B-11).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from boxmunge.commands.health_cmd import HealthCheck
from boxmunge.cve.scan_state import SCAN_MAX_AGE, read_scan_state, scan_problem
from boxmunge.manifest import ManifestError, load_manifest
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
    for project_dir in sorted(paths.projects.iterdir()):
        if not project_dir.is_dir():
            continue
        manifest_path = project_dir / "manifest.yml"
        if not manifest_path.exists():
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
    if off_entries:
        detail = "SECURITY OFF -- " + "; ".join(off_entries)
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



def check_cve_hardening_upcoming(paths: BoxPaths) -> HealthCheck:
    """Warn when a project has findings that quarantine from 0.12, not now.

    The hardening penalty counts a compose-only service without
    `read_only: true` (and a manifest `cap_add` / `no_new_privileges: false`);
    0.11.0 only warns. These findings are not quarantined, so they are not
    safe either: the fix is named in `boxmunge security <project>`.
    """
    registry = read_registry(paths)
    flagged: list[str] = []
    for name in deployed_among(registry.names, paths):
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
            detail="will quarantine from 0.12 (not quarantined now); add `read_only: true` "
                   "in compose.yml, declare the service in the manifest, or accept the risk "
                   "with a `security` declaration; see `boxmunge security <project>` -- "
                   + "; ".join(flagged),
        )
    return HealthCheck(name="cve-hardening", status="ok",
                       detail="no finding is waiting on the 0.12 hardening rule")
