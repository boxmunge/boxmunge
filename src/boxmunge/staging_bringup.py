# SPDX-License-Identifier: Apache-2.0
"""Bring staging up from the slot (spec Flows, Stage step 6).

The journaled Caddy staging site, the storage check (validation, isolation
against production, the copy plan), the optional data copy into staging's
own stores, `compose up` of `<project>-staging` from the slot, the Caddy
reload and the staging smoke.
"""
from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Any

from boxmunge.bind_sources import BindSourceError
from boxmunge.caddy import generate_staging_caddy_config
from boxmunge.caddy_journal import write_site
from boxmunge.compose import ComposeError, load_user_compose
from boxmunge.commands import deploy_images, deploy_storage
from boxmunge.compose_guard import compose_up_checked
from boxmunge.compose_resolve import ComposeResolveError
from boxmunge.commands.quarantine_gate import Clearance, clear_release, verify_started
from boxmunge.compose_validate import ComposeSecurityError
from boxmunge.cve.quarantine import QuarantineError, is_quarantined
from boxmunge.data_dirs import ReleaseStateError
from boxmunge.docker import (
    CaddyConfigRejected, DockerError, caddy_config_lock, caddy_reload,
)
from boxmunge.log import log_error
from boxmunge.release_target import DeployRefused, staging_release_target
from boxmunge.run_as import RunAsError, default_user_hint
from boxmunge.userns.offset import RemapError
from boxmunge.security_warn import warn_off_services, warn_writable_state
from boxmunge.staged_release import SlotError, release_dir, slot_dir, staging_target
from boxmunge.staging_copy_plan import StagingDataError
from boxmunge.staging_data import copy_production_data, prepare_destinations
from boxmunge.staging_isolation import StagingIsolationError
from boxmunge.staging_prepare import check_staging_storage, write_staging_overlay

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

# Failures generating, checking or preparing staging's files and storage.
STORAGE_ERRORS = (BindSourceError, ComposeError, ComposeSecurityError, OSError,
                  ReleaseStateError, StagingDataError, StagingIsolationError, SlotError)
# ... and the release's own refusal to start, found once its images are built.
BRING_UP_ERRORS = (*STORAGE_ERRORS, DeployRefused, DockerError, RunAsError,
                   ComposeResolveError, RemapError)


def _staging_auth(project_name: str, paths: BoxPaths) -> tuple[str, str] | None:
    """(user, bcrypt hash) from STAGING_AUTH_USER/PASS, or None if unset."""
    from boxmunge.secrets import SecretsFile, get_internal_key
    # boxmunge's own keys (Caddy basic auth), not the app's.
    secrets = SecretsFile.project(paths, project_name)
    auth_user = get_internal_key(secrets, "STAGING_AUTH_USER")
    auth_pass = get_internal_key(secrets, "STAGING_AUTH_PASS")
    if not (auth_user and auth_pass):
        return None
    import bcrypt
    hashed = bcrypt.hashpw(auth_pass.encode(), bcrypt.gensalt()).decode()
    print(f"  Staging auth enabled for user '{auth_user}'")
    return auth_user, hashed


def _decide_users(paths: BoxPaths, project: str, manifest: dict[str, Any]) -> Clearance | None:
    """Build staging's images, decide and record who each service runs as
    (deploy_images), and write the slot's overlay with those users. A
    CVE-quarantined project's staging starts only if every image it would
    start scans clean (quarantine_gate; its clearance is returned, to check
    what the start ran); production stays quarantined."""
    slot = slot_dir(paths, project)
    print("  Building images and deciding who each service runs as...")
    try:
        users = deploy_images.prepare_release_users(
            paths, staging_release_target(paths, project), manifest, component="stage")
        clearance = (clear_release(paths, staging_release_target(paths, project), manifest)
                     if is_quarantined(project, paths) else None)
    except (RunAsError, ComposeResolveError) as e:
        raise DeployRefused([str(e)]) from e
    write_staging_overlay(paths, project, manifest, release_dir(slot), slot, users)
    deploy_images.record_release_users(paths, staging_release_target(paths, project),
                                       manifest, users, component="stage")
    return clearance


def _prepare_storage(paths: BoxPaths, project: str,
                     manifest: dict[str, Any]) -> Clearance | None:
    """Decide staging's users, check staging's files from the slot and,
    with copy_data, copy production's data into staging's created, never
    started containers. Returns the quarantine gate's clearance, if any."""
    clearance = _decide_users(paths, project, manifest)
    release = release_dir(slot_dir(paths, project))
    user_compose = load_user_compose(release / "compose.yml", project)
    # Deploy-time warnings, repeated by design (spec "Deploy-time warning").
    warn_off_services(paths, manifest, component="stage")
    warn_writable_state(paths, manifest, user_compose, component="stage")
    plan = check_staging_storage(paths, project, manifest)
    if plan is not None:
        prepare_destinations(paths, project, plan)
    deploy_storage.prepare_storage(paths, staging_release_target(paths, project))
    if plan is None:
        return clearance
    # Create staging (and so its volumes) without starting it, then copy
    # into it while neither side runs.
    print("  Creating staging containers for the data copy...")
    compose_up_checked(paths, project, component="stage", staging=True,
                       record=True, deploying=True, build=False, start=False,
                       pinned=is_quarantined(project, paths))
    copy_production_data(paths, project, plan)
    print("  Data copy complete.")
    return clearance


def _reload_caddy(paths: BoxPaths, project: str) -> bool:
    site = paths.project_staging_caddy_site(project).name
    print("  Reloading Caddy...")
    try:
        caddy_reload(paths.caddy, paths.state)
    except CaddyConfigRejected as e:
        restored = ", ".join(e.restored) or "(nothing journaled)"
        print(f"ERROR: Caddy rejected the staging site config ({site}); the "
              f"previous routing was restored for: {restored}.", file=sys.stderr)
        if e.refused:
            print(f"ERROR: some site files were not restored: {e.refused}", file=sys.stderr)
        log_error("stage", f"Caddy rejected {site}; previous routing restored for: "
                  f"{restored}" + (f"; refused: {e.refused}" if e.refused else ""),
                  paths, project=project)
        return False
    except DockerError as e:
        print(f"  WARN: Caddy reload failed: {e}")
    return True


def bring_up_staging(paths: BoxPaths, project: str, manifest: dict[str, Any]) -> int:
    """Run staging from the slot. Returns 0, or 1 with the failure reported
    (the caller tears the stage down)."""
    release = release_dir(slot_dir(paths, project))
    print(f"Staging {project}...")
    try:
        staging_auth = _staging_auth(project, paths)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    # Journaled like production's site: if Caddy rejects it, the reload
    # restores the last accepted config instead of leaving it to break the
    # next reload of every project.
    staging_conf = paths.project_staging_caddy_site(project)
    try:
        staging_conf.parent.mkdir(parents=True, exist_ok=True)
        with caddy_config_lock(paths.state):
            write_site(paths.caddy, staging_conf,
                       generate_staging_caddy_config(manifest, auth=staging_auth))
        clearance = _prepare_storage(paths, project, manifest)
    except DeployRefused as e:
        print(f"  ERROR: Staging cannot start as it is:\n{e}", file=sys.stderr)
        print("  Staging was not started.", file=sys.stderr)
        log_error("stage", f"Stage refused: {e}", paths, project=project)
        return 1
    except BRING_UP_ERRORS as e:
        print(f"  ERROR: Preparing staging's storage failed: {e}", file=sys.stderr)
        print("  Staging was not started.", file=sys.stderr)
        log_error("stage", f"Preparing staging storage failed: {e}", paths, project=project)
        return 1
    print("  Starting staging containers...")
    try:
        # A quarantined project's staging starts only the images it scanned.
        compose_up_checked(paths, project, component="stage", staging=True, record=True,
                           deploying=True, build=False, pinned=is_quarantined(project, paths))
    except DockerError as e:
        print(f"  ERROR: {e}", file=sys.stderr)
        log_error("stage", f"Stage failed: {e}", paths, project=project)
        return 1
    if clearance is not None:
        # The scan was by tag: a tag another project pulled since would have
        # staged an image nobody scanned.
        try:
            verify_started(paths, clearance, "stage")
        except (QuarantineError, DockerError) as e:
            print(f"  ERROR: Staging does not run what was scanned: {e}", file=sys.stderr)
            log_error("stage", f"Stage refused after the start: {e}", paths, project=project)
            return 1
    if not _reload_caddy(paths, project):
        return 1
    if any(svc.get("smoke") for svc in manifest.get("services", {}).values()):
        print("  Running smoke tests in containers...")
        from boxmunge.commands.check import run_smoke_in_container
        target = staging_target(paths, project)
        result = run_smoke_in_container(
            release, manifest, [], project_name=target.project_name, logs_target=target,
            hint=lambda svc: default_user_hint(paths, project, svc, staging=True))
        if result.status == "ok":
            print("  Smoke tests passed.")
        else:
            print(f"  WARN: Smoke test {result.status}: {result.message}")
    return 0
