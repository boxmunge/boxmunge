"""boxmunge stage <project> — stage from latest source alongside production."""
from __future__ import annotations

import subprocess
import sys
from typing import TYPE_CHECKING, Any

from boxmunge.caddy import generate_staging_caddy_config
from boxmunge.caddy_journal import write_site
from boxmunge.commands.unstage_cmd import teardown_staging
from boxmunge.compose import generate_staging_compose_base, generate_staging_compose_override
from boxmunge.docker import (
    CaddyConfigRejected, DockerError, caddy_config_lock, caddy_reload, compose_up,
)
from boxmunge.fileutil import atomic_write_text, project_lock, LockError
from boxmunge.identity import register_project_identity
from boxmunge.intake import (
    IntakeError, check_installable, extract_candidate, incoming_workspace,
    report_refusal, validate_release_tree,
)
from boxmunge.lifecycle import is_blocked
from boxmunge.log import log_operation, log_error
from boxmunge.project_registry import is_registered
from boxmunge.release import install_release, keep_prestage_release, live_ref, mark_live
from boxmunge.security_warn import warn_off_services, warn_writable_state
from boxmunge.source import SourceError, bundle_ref, consume_bundle, resolve_bundle_source
from boxmunge.state import write_state

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


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
                print(f"ERROR: Keeping the production release failed: {e}. "
                      f"Nothing was changed.", file=sys.stderr)
                return 1
            try:
                install_release(tree, project_dir)
                mark_live(paths, project_name, bundle_ref(bundle_path))
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


def _run_stage_inner(project_name: str, paths: BoxPaths, ref: str | None = None,
                     dry_run: bool = False) -> int:
    """Inner stage logic — caller must hold the project lock."""
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
    from boxmunge.secrets import LegacySecretError, SecretsFile, get_key
    secrets = SecretsFile.project(paths, project_name)
    try:
        auth_user = get_key(secrets, "STAGING_AUTH_USER")
        auth_pass = get_key(secrets, "STAGING_AUTH_PASS")
    except LegacySecretError as e:
        raise ValueError(
            f"{e}, so its value is ambiguous. Set it again: "
            f"secrets set {project_name} '{e.key}=<value>'"
        ) from e
    if not (auth_user and auth_pass):
        return None
    import bcrypt
    hashed = bcrypt.hashpw(auth_pass.encode(), bcrypt.gensalt()).decode()
    print(f"  Staging auth enabled for user '{auth_user}'")
    return auth_user, hashed


def _bring_up_staging(project_name: str, paths: BoxPaths,
                      manifest: dict[str, Any], ref: str | None) -> int:
    """Write staging config, start staging containers, smoke-test, record."""
    project_dir = paths.project_dir(project_name)
    print(f"Staging {project_name}...")
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

    # Build env_files for staging (same as production)
    staging_env_files = {}
    if paths.host_secrets.exists():
        staging_env_files["host_secrets"] = str(paths.host_secrets)
    project_env = project_dir / "project.env"
    if project_env.exists():
        staging_env_files["project_env"] = "./project.env"
    project_secrets = paths.project_secrets(project_name)
    if project_secrets.exists():
        staging_env_files["project_secrets"] = "./secrets.env"

    staging_override = paths.project_staging_compose_override(project_name)
    # mode=0o644: read by `docker compose` which runs in deploy/root contexts
    # but the file is also read inside the Caddy/compose toolchain — keep
    # consistent with the site config above.
    # v0.8: thread the user compose through so the overlay can omit
    # read_only/tmpfs defaults on services where the user already declared them.
    from boxmunge.compose import load_user_compose
    user_compose = load_user_compose(project_dir / "compose.yml", project_name)
    atomic_write_text(staging_override, generate_staging_compose_override(
        manifest, env_files=staging_env_files or None,
        user_compose=user_compose,
    ), mode=0o644)

    # Deploy-time warning for any service resolving to profile: off.
    # Repeated by design — see spec §"Deploy-time warning".
    warn_off_services(paths, manifest, component="stage")
    # v0.9: writable surface visibility (read_only:false WARN, external INFO).
    warn_writable_state(paths, manifest, user_compose, component="stage")

    # Generate staging base (compose.yml with ports stripped to avoid conflicts)
    staging_base = project_dir / "compose.staging-base.yml"
    # mode=0o644: same rationale as the override above.
    atomic_write_text(staging_base, generate_staging_compose_base(project_dir / "compose.yml"), mode=0o644)

    # Copy production data to staging if opted in
    if manifest.get("staging", {}).get("copy_data"):
        print("  Snapshotting production data for staging...")
        from boxmunge.staging_data import snapshot_prod_data
        try:
            snapshot_prod_data(project_name, project_dir, manifest)
            print("  Data snapshot complete.")
        except Exception as e:
            print(f"  ERROR: Data snapshot failed: {e}", file=sys.stderr)
            log_error("stage", f"Data snapshot failed: {e}", paths, project=project_name)
            return 1

    # Start staging containers with separate project name
    print("  Starting staging containers...")
    staging_project_name = f"{project_name}-staging"
    compose_files = ["compose.staging-base.yml", "compose.boxmunge-staging.yml"]
    try:
        compose_up(project_dir, compose_files=compose_files,
                   project_name=staging_project_name)
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
        log_error("stage", f"Caddy rejected {site}; previous routing restored",
                  paths, project=project_name)
        return 1
    except DockerError as e:
        print(f"  WARN: Caddy reload failed: {e}")

    # Per-service smoke tests — exec inside staging containers
    has_smoke = any(svc.get("smoke") for svc in manifest.get("services", {}).values())
    if has_smoke:
        print("  Running smoke tests in containers...")
        from boxmunge.commands.check import run_smoke_in_container
        staging_compose_files = ["compose.staging-base.yml", "compose.boxmunge-staging.yml"]
        smoke_result = run_smoke_in_container(
            project_dir, manifest, staging_compose_files,
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
    """Stage a project. Returns 0 on success, 1 on failure."""
    block = is_blocked(project_name, paths)
    if block:
        print(f"ERROR: {block.refuse_message}", file=sys.stderr)
        return 1
    if not is_registered(project_name, paths):
        print(f"ERROR: Project '{project_name}' is not registered on this server. "
              f"Run: project-add {project_name}", file=sys.stderr)
        return 1

    try:
        with project_lock(project_name, paths):
            return _run_stage_inner(project_name, paths, ref, dry_run)
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
