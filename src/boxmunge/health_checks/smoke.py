# SPDX-License-Identifier: Apache-2.0
"""Project-level smoke test runner.

Wraps boxmunge.commands.check.run_smoke_in_container with the bookkeeping
needed by the resume / security-resume flows (manifest load, compose-file
list assembly). Lives outside commands/ so cross-flow callers don't need
function-level lazy imports of commands/resume_cmd (audit A-2).
"""
from __future__ import annotations

from boxmunge.manifest import load_manifest
from boxmunge.paths import BoxPaths


def run_smoke(project_name: str, paths: BoxPaths) -> tuple[bool, str]:
    """Run the per-project smoke test inside the container.

    Returns (passed, message). When the manifest declares no smoke test,
    returns (True, "no smoke test configured") — callers treat that as a
    clean pass.
    """
    # Imported lazily so the `boxmunge.commands.check` module's heavier
    # subprocess machinery isn't pulled in for callers that never run a
    # smoke check (e.g. `boxmunge security <project>` introspection).
    from boxmunge.commands.check import run_smoke_in_container

    project_dir = paths.project_dir(project_name)
    manifest = load_manifest(paths.project_manifest(project_name))
    services = manifest.get("services", {})
    has_smoke = any(svc.get("smoke") for svc in services.values())
    if not has_smoke:
        return True, "no smoke test configured"
    compose_files = ["compose.yml"]
    override = paths.project_compose_override(project_name)
    if override.exists():
        compose_files.append("compose.boxmunge.yml")
    result = run_smoke_in_container(
        project_dir, manifest, compose_files, project_name=project_name,
    )
    return result.status == "ok", result.message
