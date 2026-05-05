# SPDX-License-Identifier: Apache-2.0
"""Health check: container hardening profile status across projects.

Surfaces any service whose effective security profile is `off` so the
operator sees the un-hardened surface during routine `boxmunge health`
runs (not only at deploy time).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from boxmunge.commands.health_cmd import HealthCheck
from boxmunge.manifest import ManifestError, load_manifest
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
