# SPDX-License-Identifier: Apache-2.0
"""Generate and check staging's compose files.

Staging's files are written beside the release they run (the slot, or a
check dir for a candidate) and resolved from it. `stage` checks the
candidate before anything changes: against production as it runs and as
it would run once the candidate is promoted (see staging_isolation). The
slot's files are checked again before staging's storage is prepared.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from boxmunge.bind_mounts import project_relative
from boxmunge.compose import generate_staging_compose_override, load_user_compose
from boxmunge.compose_mounts import has_env_substitution
from boxmunge.compose_validate import validate_user_compose
from boxmunge.fileutil import atomic_write_text
from boxmunge.release import project_data_dirs
from boxmunge.security_overlay import services_with_off_profile
from boxmunge.staged_release import (
    STAGING_BASE, STAGING_OVERLAY, release_dir, slot_dir, staging_target, staging_target_for,
)
from boxmunge.staging_compose import generate_staging_compose_base
from boxmunge.staging_copy_plan import CopyPlan, StagingDataError, copy_sources
from boxmunge.staging_data import plan_staging_copy
from boxmunge.staging_isolation import (
    StagingIsolationError, candidate_model, check_isolation, production_model, resolving,
    separation_problems, staging_model,
)

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def env_files_for_staging(paths: BoxPaths, project: str, release: Path) -> dict[str, str]:
    """Host secrets (absolute), the staged project.env (relative: it resolves
    in the release), and the project's secrets.env by absolute path."""
    env: dict[str, str] = {}
    if paths.host_secrets.exists():
        env["host_secrets"] = str(paths.host_secrets)
    if (release / "project.env").exists():
        env["project_env"] = "./project.env"
    if paths.project_secrets(project).exists():
        env["project_secrets"] = str(paths.project_secrets(project))
    return env


def write_staging_files(paths: BoxPaths, project: str, manifest: dict[str, Any],
                        release: Path, dest_dir: Path) -> dict:
    """Write staging's base and overlay for the release in ``release`` into
    ``dest_dir``; returns the resolved user compose model."""
    box_state = project_data_dirs(paths.project_dir(project), release).box_state()
    user_compose = load_user_compose(release / "compose.yml", project)
    # mode=0o644: read by `docker compose` in deploy and root contexts.
    atomic_write_text(dest_dir / STAGING_OVERLAY, generate_staging_compose_override(
        manifest, env_files=env_files_for_staging(paths, project, release) or None,
        user_compose=user_compose), mode=0o644)
    atomic_write_text(dest_dir / STAGING_BASE, generate_staging_compose_base(
        release / "compose.yml", box_state, paths.project_dir(project)), mode=0o644)
    return user_compose


def _read_file_entries(svc: dict[str, Any]) -> list[tuple[str, Any]]:
    """(key, path) of each env and label file a service requires."""
    found = []
    for key in ("env_file", "label_file"):
        value = svc.get(key)
        for entry in value if isinstance(value, list) else [] if value is None else [value]:
            if isinstance(entry, dict):
                if entry.get("required", True) is not False:
                    found.append((key, entry.get("path")))
            else:
                found.append((key, entry))
    return found


def require_read_files(base: Path, release: Path, project: str, project_dir: Path) -> None:
    """Refuse a staging base whose services require an env or label file in
    the project that does not exist: staging could not start, and some
    Compose versions (2.35) cannot even resolve the base to validate it. A
    path leaving the project, or using substitution, is validation's to
    refuse."""
    doc = yaml.safe_load(base.read_text())
    services = doc.get("services") if isinstance(doc, dict) else None
    missing = []
    for name, svc in (services.items() if isinstance(services, dict) else ()):
        for key, ref in _read_file_entries(svc) if isinstance(svc, dict) else []:
            if not isinstance(ref, str) or not ref or has_env_substitution(ref):
                continue
            path = os.path.normpath(os.path.join(release, os.path.expanduser(ref)))
            if project_relative(path, project_dir) is not None and not os.path.exists(path):
                missing.append(f"service {name} {key} {path}")
    if missing:
        raise StagingDataError(
            "staging could not start: these files its services read do not exist: "
            + "; ".join(missing) + f". Create each one (the project's secrets with "
            f"`secrets set {project} KEY=value`), or mark the env_file "
            f"`required: false`; then stage again.")


def validate_staging_base(paths: BoxPaths, project: str, manifest: dict[str, Any],
                          files_dir: Path, release: Path) -> None:
    """Validate staging's base where it runs: from ``release``."""
    require_read_files(files_dir / STAGING_BASE, release, project, paths.project_dir(project))
    validate_user_compose(
        files_dir / STAGING_BASE, paths, project_name=project,
        off_services={svc for svc, _ in services_with_off_profile(manifest)},
        cve_policy=manifest.get("security"), manifest_services=manifest.get("services"),
        project_directory=release)


def _refuse_shared(paths: BoxPaths, project: str, staging: dict[str, Any], release: Path,
                   productions: list[tuple[str, dict[str, Any]]]) -> None:
    """I3 on staging's model, then nothing shared with any production."""
    problems = separation_problems(staging, paths.project_dir(project), release)
    if problems:
        raise StagingIsolationError(
            "staging cannot be kept apart from production:\n  - " + "\n  - ".join(problems))
    check_isolation(paths, project, staging, productions)


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
    """Refuse a candidate staging cannot be kept apart from production as it
    runs and as it would run after promoting it, before anything changes."""
    check_dir = workspace / "staging-check"
    check_dir.mkdir()
    write_staging_files(paths, project, manifest, tree, check_dir)
    validate_staging_base(paths, project, manifest, check_dir, tree)
    with resolving():
        staging = staging_model(staging_target_for(tree, check_dir, project))
        productions = []
        now = production_model(paths, project)
        if now is not None:
            productions.append(("production", now))
        productions.append(("production after promoting this release",
                            candidate_model(paths, project, tree, manifest, check_dir)))
    _refuse_shared(paths, project, staging, tree, productions)
    if copy_sources(manifest) is None:  # with copy_data, the plan says (after the swap)
        require_staging_files(staging, paths.project_dir(project), set())


def check_staging_storage(paths: BoxPaths, project: str,
                          manifest: dict[str, Any]) -> CopyPlan | None:
    """Validate the slot's staging files, prove staging disjoint from
    production, and plan the copy. Returns the plan, or None."""
    slot = slot_dir(paths, project)
    validate_staging_base(paths, project, manifest, slot, release_dir(slot))
    with resolving():
        staging = staging_model(staging_target(paths, project))
        prod = production_model(paths, project)
    _refuse_shared(paths, project, staging, release_dir(slot),
                   [("production", prod)] if prod else [])
    plan = None
    if copy_sources(manifest) is not None:
        if prod is None:
            print("  NOTE: production was never deployed, so there is no data to copy.")
        else:
            print("  Planning the copy of production data...")
            plan = plan_staging_copy(paths, project, manifest, prod, staging)
    copied = {dest.ref for _, dest in plan.pairs if dest.kind == "bind"} if plan else set()
    require_staging_files(staging, paths.project_dir(project), copied)
    return plan
