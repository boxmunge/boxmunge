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

import json
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from boxmunge.commands.health_cmd import HealthCheck
from boxmunge.manifest import ManifestError, load_manifest
from boxmunge.project_registry import load_deployed_projects

# The scan runs daily (03:00-03:30); 36h tolerates one late or missed run's
# worth of jitter without crying wolf, and catches a second missed night.
SCAN_MAX_AGE = timedelta(hours=36)
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


def _scan_problem(paths: BoxPaths, project: str, now: datetime) -> str | None:
    path = paths.project_scan_state(project)
    if not path.exists():
        return f"{project}: never scanned"
    try:
        state = json.loads(path.read_text())
        scanned_at = datetime.fromisoformat(state["scanned_at"])
    except (OSError, ValueError, KeyError, TypeError) as e:
        return f"{project}: scan state unreadable ({e})"
    if scanned_at.tzinfo is None:
        scanned_at = scanned_at.replace(tzinfo=timezone.utc)
    age = now - scanned_at
    if age > SCAN_MAX_AGE:
        return f"{project}: last scanned {age.days}d {age.seconds // 3600}h ago"
    unscanned = state.get("unscanned") or []
    if unscanned:
        return f"{project}: last scan incomplete ({'; '.join(unscanned)})"
    return None


def check_cve_scan_freshness(paths: BoxPaths, *, now: datetime | None = None) -> HealthCheck:
    """Warn when any deployed project's CVE scan is stale or incomplete."""
    now = now or datetime.now(timezone.utc)
    projects = load_deployed_projects(paths)
    if not projects:
        return HealthCheck(name="cve-scan", status="ok", detail="no projects deployed")
    problems = [p for p in (_scan_problem(paths, name, now) for name in projects) if p]
    if problems:
        return HealthCheck(
            name="cve-scan", status="warn",
            detail="unprotected by CVE quarantine until scanned -- " + "; ".join(problems),
        )
    return HealthCheck(
        name="cve-scan", status="ok",
        detail=f"all {len(projects)} deployed projects scanned within {int(SCAN_MAX_AGE.total_seconds() // 3600)}h",
    )

