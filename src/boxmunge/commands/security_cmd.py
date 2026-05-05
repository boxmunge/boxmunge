# SPDX-License-Identifier: Apache-2.0
"""boxmunge security <project> — introspect effective container security posture."""
from __future__ import annotations

import json
import sys
from typing import Any

from boxmunge.manifest import ManifestError, load_manifest
from boxmunge.paths import BoxPaths
from boxmunge.security_overlay import (
    PROFILE_DEFAULT,
    resolve_security,
    services_with_off_profile,
)


USAGE = """\
Usage: boxmunge security <project> [--json]

Show the effective container hardening posture for each service in <project>,
after profile resolution and any per-service overrides.
"""


def _paths() -> BoxPaths:
    return BoxPaths()


def _resolved_for_each_service(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    project_sec = manifest.get("security")
    out: dict[str, dict[str, Any]] = {}
    for svc_name, svc in (manifest.get("services") or {}).items():
        svc_sec = svc.get("security") if isinstance(svc, dict) else None
        out[svc_name] = resolve_security(project_sec, svc_sec)
    return out


def _format_text(manifest: dict[str, Any]) -> str:
    project = manifest["project"]
    schema = manifest.get("schema_version", 1)
    project_sec = manifest.get("security") or {}
    project_profile = project_sec.get("profile", PROFILE_DEFAULT)

    lines = [f"project: {project} (schema_version: {schema}, profile: {project_profile})"]
    if project_sec.get("reason"):
        lines.append(f"  project reason: {project_sec['reason']!r}")
    lines.append("")

    resolved = _resolved_for_each_service(manifest)
    for svc_name, fragment in resolved.items():
        svc = manifest["services"][svc_name]
        svc_sec = svc.get("security") if isinstance(svc, dict) else None
        svc_profile = (svc_sec or {}).get("profile", project_profile)

        lines.append(f"  service: {svc_name}")
        lines.append(f"    profile:           {svc_profile}")
        if svc_sec and svc_sec.get("reason"):
            lines.append(f"    reason:            {svc_sec['reason']!r}")
        if not fragment:
            lines.append("    (no hardening applied — profile: off)")
            lines.append("")
            continue
        if "security_opt" in fragment:
            lines.append(f"    security_opt:      {fragment['security_opt']}")
        if "init" in fragment:
            lines.append(f"    init:              {fragment['init']}")
        if "pids_limit" in fragment:
            lines.append(f"    pids_limit:        {fragment['pids_limit']}")
        if "cap_drop" in fragment:
            lines.append(f"    cap_drop:          {fragment['cap_drop']}")
        if fragment.get("cap_add"):
            lines.append(f"    cap_add:           {fragment['cap_add']}")
        lines.append("")
    return "\n".join(lines)


def _format_json(manifest: dict[str, Any]) -> str:
    project = manifest["project"]
    project_sec = manifest.get("security") or {}
    payload: dict[str, Any] = {
        "project": project,
        "schema_version": manifest.get("schema_version", 1),
        "project_profile": project_sec.get("profile", PROFILE_DEFAULT),
        "project_reason": project_sec.get("reason"),
        "services": {},
        "off_services": [
            {"service": s, "reason": r}
            for s, r in services_with_off_profile(manifest)
        ],
    }
    for svc_name, fragment in _resolved_for_each_service(manifest).items():
        payload["services"][svc_name] = fragment
    return json.dumps(payload, indent=2, sort_keys=True)


def cmd_security(args: list[str]) -> None:
    if not args or args[0] in ("-h", "--help"):
        print(USAGE)
        sys.exit(0 if args else 2)

    as_json = "--json" in args
    positional = [a for a in args if not a.startswith("--")]
    if not positional:
        print(USAGE)
        sys.exit(2)
    project = positional[0]

    paths = _paths()
    manifest_path = paths.project_manifest(project)
    try:
        manifest = load_manifest(manifest_path)
    except ManifestError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    if as_json:
        print(_format_json(manifest))
    else:
        print(_format_text(manifest))
