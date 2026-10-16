# SPDX-License-Identifier: Apache-2.0
"""Generate and check staging's compose files.

`stage` checks the candidate release before installing anything: its
staging files are generated beside the unpacked bundle and resolved as if
they were in the project directory, then compared with production (see
staging_isolation). The same files, generated again once the release is
installed, are checked again before anything starts.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Any

from boxmunge.bind_mounts import project_relative
from boxmunge.compose import generate_staging_compose_override, load_user_compose
from boxmunge.compose_validate import validate_user_compose
from boxmunge.fileutil import atomic_write_text
from boxmunge.release import project_data_dirs
from boxmunge.security_overlay import services_with_off_profile
from boxmunge.staging_compose import STAGING_BASE, STAGING_OVERLAY, generate_staging_compose_base
from boxmunge.staging_copy_plan import CopyPlan, StagingDataError, copy_sources
from boxmunge.staging_data import plan_staging_copy
from boxmunge.staging_isolation import check_isolation

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def _env_files(paths: BoxPaths, project: str) -> dict[str, str]:
    env_files: dict[str, str] = {}
    if paths.host_secrets.exists():
        env_files["host_secrets"] = str(paths.host_secrets)
    if (paths.project_dir(project) / "project.env").exists():
        env_files["project_env"] = "./project.env"
    if paths.project_secrets(project).exists():
        env_files["project_secrets"] = "./secrets.env"
    return env_files


def write_staging_files(paths: BoxPaths, project: str, manifest: dict[str, Any],
                        release_dir: Path, dest_dir: Path, box_state: set[str]) -> dict:
    """Write staging's base and overlay for the release in ``release_dir``
    into ``dest_dir``; returns the resolved user compose model."""
    user_compose = load_user_compose(release_dir / "compose.yml", project)
    # mode=0o644: read by `docker compose` in deploy and root contexts.
    atomic_write_text(dest_dir / STAGING_OVERLAY, generate_staging_compose_override(
        manifest, env_files=_env_files(paths, project) or None, user_compose=user_compose,
    ), mode=0o644)
    atomic_write_text(dest_dir / STAGING_BASE, generate_staging_compose_base(
        release_dir / "compose.yml", box_state, paths.project_dir(project)), mode=0o644)
    return user_compose


def _validate(paths: BoxPaths, project: str, manifest: dict[str, Any], base: Path) -> None:
    validate_user_compose(
        base, paths, project_name=project,
        off_services={svc for svc, _ in services_with_off_profile(manifest)},
        cve_policy=manifest.get("security"), manifest_services=manifest.get("services"))


def _within(path: str, roots: set[str]) -> bool:
    return any(path == r or path.startswith(r.rstrip("/") + "/") for r in roots)


def require_staging_files(staging_model: dict[str, Any], project_dir: Path,
                          copied: set[str]) -> None:
    """Refuse a config or secret file staging reads from its own data copy
    when the file is neither there nor about to be copied there: Compose
    would refuse to create staging's containers."""
    missing = []
    for section in ("configs", "secrets"):
        for key, decl in (staging_model.get(section) or {}).items():
            path = decl.get("file") if isinstance(decl, dict) else None
            rel = project_relative(path, project_dir) if isinstance(path, str) else None
            if not rel or not rel.split(os.sep, 1)[0].endswith("-staging"):
                continue
            full = os.path.normpath(project_dir / rel)
            if not os.path.lexists(full) and not _within(full, copied):
                missing.append(f"{section[:-1]} {key} reads {full}")
    if missing:
        raise StagingDataError(
            "staging reads its own copy of data, never production's, and these "
            "files do not exist: " + "; ".join(missing) + ". Put each file there, "
            "or set staging.copy_data so stage copies production's.")


def precheck_candidate(paths: BoxPaths, project: str, manifest: dict[str, Any],
                       tree: Path, workspace: Path) -> None:
    """Refuse a candidate staging cannot be kept apart from production,
    before anything in the project dir changes."""
    check_dir = workspace / "staging-check"
    check_dir.mkdir()
    if (tree / ".env").exists():
        shutil.copy2(tree / ".env", check_dir / ".env")
    box_state = project_data_dirs(paths.project_dir(project), tree).box_state()
    write_staging_files(paths, project, manifest, tree, check_dir, box_state)
    _validate(paths, project, manifest, check_dir / STAGING_BASE)
    _, staging_model = check_isolation(paths, project, box_state, staging_dir=check_dir)
    if copy_sources(manifest) is None:  # with copy_data, the plan says (after install)
        require_staging_files(staging_model, paths.project_dir(project), set())


def check_staging_storage(paths: BoxPaths, project: str,
                          manifest: dict[str, Any]) -> CopyPlan | None:
    """Validate the installed staging model, prove it shares nothing with
    production, and plan the data copy. Returns the plan, or None when
    nothing is copied."""
    project_dir = paths.project_dir(project)
    _validate(paths, project, manifest, project_dir / STAGING_BASE)
    prod_model, staging_model = check_isolation(
        paths, project, project_data_dirs(project_dir).box_state())
    plan = None
    if copy_sources(manifest) is not None:
        if prod_model is None:
            print("  NOTE: production was never deployed, so there is no data to copy.")
        else:
            print("  Planning the copy of production data...")
            plan = plan_staging_copy(paths, project, manifest, prod_model, staging_model)
    copied = {dest.ref for _, dest in plan.pairs if dest.kind == "bind"} if plan else set()
    require_staging_files(staging_model, project_dir, copied)
    return plan
