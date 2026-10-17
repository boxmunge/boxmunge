"""boxmunge stage <project> — stage from latest source alongside production."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from boxmunge.caddy import generate_staging_caddy_config
from boxmunge.caddy_journal import write_site
from boxmunge.commands.unstage_cmd import refuse_if_promotion_interrupted, teardown_staging
from boxmunge.compose import ComposeError
from boxmunge.compose_guard import compose_up_checked
from boxmunge.compose_resolve import resolve_deployed_config
from boxmunge.compose_validate import ComposeSecurityError
from boxmunge.data_dirs import SetAsideError, log_kept, set_aside_announcer
from boxmunge.docker import (
    CaddyConfigRejected, DockerError, caddy_config_lock, caddy_reload, compose_down,
    staging_compose_project,
)
from boxmunge.fileutil import project_lock, LockError
from boxmunge.identity import register_project_identity
from boxmunge.intake import (
    IntakeError, check_installable, extract_candidate, incoming_workspace,
    report_refusal, validate_release_tree,
)
from boxmunge.lifecycle import refuse_if_blocked
from boxmunge.log import log_operation, log_error
from boxmunge.project_registry import is_registered
from boxmunge.release import (
    ReleaseStateError, install_release, live_ref, mark_live,
)
from boxmunge.release_staging import (
    has_prestage, keep_prestage_release, prestage_ref, production_release_root,
)
from boxmunge.release_txn import refuse_if_install_open
from boxmunge.security_warn import warn_off_services, warn_writable_state
from boxmunge.source import SourceError, bundle_ref, consume_bundle, resolve_bundle_source
from boxmunge.staging_compose import STAGING_BASE, STAGING_FILES, STAGING_OVERLAY
from boxmunge.staged_release import staging_target_for
from boxmunge.staging_copy_plan import CopyPlan, StagingDataError, copy_sources
from boxmunge.staging_data import copy_production_data, plan_staging_copy, prepare_destinations
from boxmunge.staging_isolation import (
    StagingIsolationError, check_isolation, production_model, resolving, staging_model,
)
from boxmunge.staging_prepare import (
    precheck_candidate, require_staging_files, validate_staging_base, write_staging_files,
)
from boxmunge.state import write_state

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

# Failures generating or checking staging's compose files.
_STORAGE_ERRORS = (ComposeError, ComposeSecurityError, OSError, ReleaseStateError,
                   StagingDataError, StagingIsolationError)


def _intake_bundle(project_name: str, paths: BoxPaths, ref: str | None,
                   dry_run: bool) -> dict[str, Any] | int:
    """Validate the inbox bundle, then install it. Returns manifest or exit code."""
    project_dir = paths.project_dir(project_name)
    is_new = not (project_dir / "manifest.yml").exists()
    try:
        bundle_path = resolve_bundle_source(project_name, paths, ref=ref)
    except SourceError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    # Unpack and validate in .releases/incoming/ before anything in the
    # project dir changes (audit C-01).
    try:
        with incoming_workspace(paths, project_name) as workspace:
            tree = extract_candidate(bundle_path, workspace)
            manifest = validate_release_tree(tree, project_name, paths, "stage")
            check_installable(tree, project_dir)
            if not is_new:
                try:
                    precheck_candidate(paths, project_name, manifest, tree, workspace)
                except _STORAGE_ERRORS as e:
                    print(f"ERROR: {e}\nNothing was changed.", file=sys.stderr)
                    log_error("stage", f"Stage refused: {e}", paths, project=project_name)
                    return 1
            if dry_run:
                print(f"[DRY RUN] Would stage '{project_name}'")
                return 0
            if is_new:
                print(f"Creating new project '{project_name}'")
            try:
                # The production release stays recoverable: promote turns it
                # into the previous release, unstage puts it back.
                keep_prestage_release(paths, project_name, tree)
            except (OSError, ValueError) as e:
                unchanged = ("Nothing else was changed" if isinstance(e, SetAsideError)
                             else "Nothing was changed")
                print(f"ERROR: Keeping the production release failed: {e}. "
                      f"{unchanged}.", file=sys.stderr)
                return 1
            try:
                kept = install_release(tree, project_dir,
                                       set_aside_announcer(paths, project_name, "stage"))
                mark_live(paths, project_name, bundle_ref(bundle_path))
                log_kept(paths, project_name, kept, "stage")
            except (OSError, ValueError) as e:
                print(f"ERROR: Installing the staged release failed: {e}",
                      file=sys.stderr)
                if not teardown_staging(project_name, paths):
                    print(f"ERROR: Putting production back was incomplete; "
                          f"run 'unstage {project_name}'.", file=sys.stderr)
                return 1
    except IntakeError as e:
        return report_refusal(e)

    register_project_identity(project_name, manifest.get("id", ""), paths)
    consume_bundle(bundle_path, project_name, paths)
    return manifest


def _checkout_repo(project_name: str, paths: BoxPaths, ref: str | None,
                   dry_run: bool) -> dict[str, Any] | int:
    """Repo-sourced project: check out ref, validate on disk. Manifest or exit code."""
    project_dir = paths.project_dir(project_name)
    repo_dir = project_dir / "repo"
    if ref:
        print(f"  Fetching ref {ref}...")
        try:
            subprocess.run(["git", "fetch", "origin"], cwd=repo_dir,
                           check=True, capture_output=True, text=True)
            subprocess.run(["git", "checkout", ref], cwd=repo_dir,
                           check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            print(f"ERROR: Git checkout failed: {e.stderr}", file=sys.stderr)
            return 1
    try:
        manifest = validate_release_tree(project_dir, project_name, paths, "stage")
    except IntakeError as e:
        return report_refusal(e)
    if dry_run:
        print(f"[DRY RUN] Would stage '{project_name}'")
        return 0
    return manifest


def stage_locked(project_name: str, paths: BoxPaths, ref: str | None = None,
                 dry_run: bool = False) -> int:
    """The stage core. Caller holds the project lock; never takes it.

    Eligibility is checked here, under the lock, immediately before
    anything changes.
    """
    if refuse_if_blocked(project_name, paths):
        return 1
    # A stage would install over the half-installed release and take it as
    # production's own, losing the open install's rollback target.
    if refuse_if_install_open(paths, project_name, component="stage"):
        return 1
    if not is_registered(project_name, paths):
        print(f"ERROR: Project '{project_name}' is not registered on this server. "
              f"Run: project-add {project_name}", file=sys.stderr)
        return 1
    if refuse_if_promotion_interrupted(project_name, paths):
        return 1
    project_dir = paths.project_dir(project_name)
    is_new = not (project_dir / "manifest.yml").exists()

    if is_new or not (project_dir / "repo").exists():
        result = _intake_bundle(project_name, paths, ref, dry_run)
    else:
        result = _checkout_repo(project_name, paths, ref, dry_run)
    if isinstance(result, int):
        return result

    # From here on the staged release is installed: any failure tears the
    # stage down again and puts production's release back (audit C-13).
    succeeded = False
    try:
        rc = _bring_up_staging(project_name, paths, result, ref)
        succeeded = rc == 0
        return rc
    finally:
        if not succeeded:
            print("  Stage failed; cleaning up...")
            if teardown_staging(project_name, paths):
                print(f"  Staging for '{project_name}' cleaned up.")
            else:
                print(f"ERROR: Cleanup after the failed stage was incomplete; "
                      f"run 'unstage {project_name}'.", file=sys.stderr)


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


def _retire_previous_staging(project_name: str, paths: BoxPaths) -> None:
    """A re-stage replaces staging: take the running one down (its data is
    kept) before its compose files are rewritten and its data replaced."""
    project_dir = paths.project_dir(project_name)
    if not (project_dir / STAGING_OVERLAY).exists():
        return
    base = STAGING_BASE if (project_dir / STAGING_BASE).exists() else "compose.yml"
    print("  Stopping the previous staging...")
    compose_down(project_dir, compose_files=[base, STAGING_OVERLAY],
                 project_name=staging_compose_project(project_name))


def _prestage_production(paths: BoxPaths, project_name: str) -> dict[str, Any] | None:
    """Production's model while the staged release is installed in the
    project dir: from the kept release, or None if it never deployed."""
    if has_prestage(paths, project_name) and prestage_ref(paths, project_name) is None:
        return None
    root = production_release_root(paths, project_name)
    if root == paths.project_dir(project_name):
        return production_model(paths, project_name)
    env = root / ".env"
    return resolve_deployed_config(
        paths.project_dir(project_name),
        [str(root / "compose.yml"), paths.project_compose_override(project_name).name],
        project_name, all_profiles=True, project_directory=paths.project_dir(project_name),
        env_file=env if env.exists() else Path(os.devnull))


def _check_prestage_storage(paths: BoxPaths, project_name: str,
                            manifest: dict[str, Any]) -> CopyPlan | None:
    """staging_prepare.check_staging_storage for this interim layout, where
    staging runs from the project dir and production from its kept release;
    it goes, with _prestage_production, when stage builds the slot."""
    project_dir = paths.project_dir(project_name)
    validate_staging_base(paths, project_name, manifest, project_dir, project_dir)
    with resolving():
        staging = staging_model(staging_target_for(project_dir, project_dir, project_name))
        prod = _prestage_production(paths, project_name)
    check_isolation(paths, project_name, staging, [("production", prod)] if prod else [])
    plan = None
    if copy_sources(manifest) is not None and prod is not None:
        print("  Planning the copy of production data...")
        plan = plan_staging_copy(paths, project_name, manifest, prod, staging)
    copied = {dest.ref for _, dest in plan.pairs if dest.kind == "bind"} if plan else set()
    require_staging_files(staging, project_dir, copied)
    return plan


def _bring_up_staging(project_name: str, paths: BoxPaths,
                      manifest: dict[str, Any], ref: str | None) -> int:
    """Write staging config, start staging containers, smoke-test, record."""
    project_dir = paths.project_dir(project_name)
    print(f"Staging {project_name}...")
    try:
        _retire_previous_staging(project_name, paths)
    except DockerError as e:
        print(f"ERROR: Stopping the previous staging failed: {e}", file=sys.stderr)
        return 1
    # Staging auth — inject basicauth if secrets are set
    try:
        staging_auth = _staging_auth(project_name, paths)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    # Journaled like production's site: if Caddy rejects it, the reload
    # restores the last accepted config instead of leaving it to break the
    # next reload of every project.
    staging_conf = paths.project_staging_caddy_site(project_name)
    staging_conf.parent.mkdir(parents=True, exist_ok=True)
    with caddy_config_lock(paths.state):
        write_site(paths.caddy, staging_conf,
                   generate_staging_caddy_config(manifest, auth=staging_auth))

    # The staging files: compose.yml and its overlay, sharing no resource
    # with production (checked below, before anything starts).
    try:
        user_compose = write_staging_files(paths, project_name, manifest, project_dir,
                                           project_dir)
    except _STORAGE_ERRORS as e:
        print(f"  ERROR: Writing staging's compose files failed: {e}", file=sys.stderr)
        return 1

    # Deploy-time warning for any service resolving to profile: off.
    # Repeated by design — see spec §"Deploy-time warning".
    warn_off_services(paths, manifest, component="stage")
    # v0.9: writable surface visibility (read_only:false WARN, external INFO).
    warn_writable_state(paths, manifest, user_compose, component="stage")

    staging_project_name = staging_compose_project(project_name)
    try:
        plan = _check_prestage_storage(paths, project_name, manifest)
        if plan is not None:
            # Create staging (and so its volumes) without starting it, then
            # copy into it while neither side runs.
            prepare_destinations(paths, project_name, plan)
            print("  Creating staging containers for the data copy...")
            compose_up_checked(paths, project_name, component="stage",
                               compose_files=STAGING_FILES, staging=True, prestage=True, record=True,
                               deploying=True, start=False)
            copy_production_data(paths, project_name, plan, prestage=True)
            print("  Data copy complete.")
    except (*_STORAGE_ERRORS, DockerError) as e:
        print(f"  ERROR: Preparing staging's storage failed: {e}", file=sys.stderr)
        print("  Staging was not started.", file=sys.stderr)
        log_error("stage", f"Preparing staging storage failed: {e}", paths,
                  project=project_name)
        return 1

    # Start staging containers with separate project name
    print("  Starting staging containers...")
    try:
        compose_up_checked(paths, project_name, component="stage",
                           compose_files=STAGING_FILES, staging=True, prestage=True, record=True,
                           deploying=True)
    except DockerError as e:
        print(f"  ERROR: {e}", file=sys.stderr)
        log_error("stage", f"Stage failed: {e}", paths, project=project_name)
        return 1

    # Reload Caddy
    print("  Reloading Caddy...")
    try:
        caddy_reload(paths.caddy, paths.state)
    except CaddyConfigRejected as e:
        site = paths.project_staging_caddy_site(project_name).name
        restored = ", ".join(e.restored) or "(nothing journaled)"
        print(f"ERROR: Caddy rejected the staging site config ({site}); the "
              f"previous routing was restored for: {restored}.", file=sys.stderr)
        if e.refused:
            print(f"ERROR: some site files were not restored: {e.refused}",
                  file=sys.stderr)
        log_error("stage", f"Caddy rejected {site}; previous routing restored for: "
                  f"{restored}" + (f"; refused: {e.refused}" if e.refused else ""),
                  paths, project=project_name)
        return 1
    except DockerError as e:
        print(f"  WARN: Caddy reload failed: {e}")

    # Per-service smoke tests — exec inside staging containers
    has_smoke = any(svc.get("smoke") for svc in manifest.get("services", {}).values())
    if has_smoke:
        print("  Running smoke tests in containers...")
        from boxmunge.commands.check import run_smoke_in_container
        smoke_result = run_smoke_in_container(
            project_dir, manifest, STAGING_FILES,
            project_name=staging_project_name,
        )
        if smoke_result.status == "ok":
            print("  Smoke tests passed.")
        else:
            print(f"  WARN: Smoke test {smoke_result.status}: {smoke_result.message}")

    # Record staging state
    staged_ref = ref if (project_dir / "repo").exists() else live_ref(paths, project_name)
    write_state(paths.project_staging_state(project_name), {
        "active": True,
        "ref": staged_ref or "latest",
    })

    staging_hosts = [f"staging.{h}" for h in manifest.get("hosts", [])]
    print("  Staged at:")
    for h in staging_hosts:
        print(f"    https://{h}")
    print(f"  Run 'promote {project_name}' to go live, or 'unstage {project_name}' to tear down.")

    log_operation("stage", "Staged", paths, project=project_name)

    from boxmunge.webhooks import webhook_safe
    webhook_safe("stage", project_name, paths, details={"ref": staged_ref or "latest"})

    return 0


def run_stage(project_name: str, paths: BoxPaths, ref: str | None = None,
              dry_run: bool = False) -> int:
    """stage: take the project lock and stage. Returns 0 on success, 1 on failure."""
    try:
        with project_lock(project_name, paths):
            return stage_locked(project_name, paths, ref, dry_run)
    except LockError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


def cmd_stage(args: list[str]) -> None:
    from boxmunge.commands.argv import parse_args, require_project_name
    from boxmunge.paths import BoxPaths
    parsed = parse_args(
        "stage", args, flags={"--dry-run"}, options={"--ref"},
        min_positional=1, max_positional=1,
    )
    project = require_project_name("stage", parsed.positional[0])
    sys.exit(run_stage(project, BoxPaths(), ref=parsed.get("--ref"),
                       dry_run=parsed.has("--dry-run")))
