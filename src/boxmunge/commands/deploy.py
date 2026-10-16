# SPDX-License-Identifier: Apache-2.0
"""boxmunge prod-deploy <project> — full deployment flow."""

import shlex
import subprocess
import sys
from pathlib import Path

from boxmunge.caddy import prepare_caddy_config
from boxmunge.commands.deploy_steps import (
    post_deploy_diagnostics, record_deploy_state, smoke_ok,
    snapshot_live_release, take_pre_deploy_snapshot, update_repo,
)
from boxmunge.compose import prepare_compose_override
from boxmunge.docker import CaddyConfigRejected, compose_up, caddy_reload, DockerError
from boxmunge.fileutil import project_lock, LockError
from boxmunge.identity import register_project_identity
from boxmunge.intake import (
    IntakeError, check_installable, extract_candidate, incoming_workspace,
    report_refusal, validate_release_tree,
)
from boxmunge.lifecycle import is_blocked
from boxmunge.log import log_operation, log_error
from boxmunge.manifest import load_manifest, ManifestError
from boxmunge.paths import BoxPaths
from boxmunge.probation import clear_probation_if_active
from boxmunge.release import (
    ReleaseStateError, has_prestage, install_release, keep_previous_release,
    discard_prestage, discard_previous_release, live_ref, mark_live, prestage_ref,
    prestage_to_previous, prestage_tree, previous_dir, sync_live_scripts,
)
from boxmunge.source import (
    SourceError, bundle_ref, consume_bundle, resolve_bundle_source,
)
from boxmunge.state import read_state


def _run_deploy_inner(
    project_name: str,
    paths: BoxPaths,
    ref: str | None = None,
    no_snapshot: bool = False,
    dry_run: bool = False,
    component: str = "deploy",
    staged: bool = False,
) -> int:
    """Inner deploy logic — caller must hold the project lock."""
    project_dir = paths.project_dir(project_name)
    is_new = not (project_dir / "manifest.yml").exists()

    # Git projects have a repo/ dir and pull their code in place. Bundle
    # projects take a release from the inbox.
    if not is_new and (project_dir / "repo").exists():
        return _deploy_repo(project_name, paths, ref, no_snapshot, dry_run, component)

    if staged:
        return _promote_staged(project_name, paths, no_snapshot, dry_run, component)
    if has_prestage(paths, project_name):
        print(f"ERROR: '{project_name}' has a staged release installed. Run "
              f"'promote {project_name}' to deploy it, or 'unstage "
              f"{project_name}' to discard it, first.", file=sys.stderr)
        return 1

    try:
        bundle_path = resolve_bundle_source(project_name, paths, ref=ref)
    except SourceError as e:
        if is_new or ref:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        print(f"No new bundle for '{project_name}' in the inbox; "
              f"redeploying the release already on disk.")
        return redeploy_installed(project_name, paths, None, no_snapshot,
                                  dry_run, component)
    return _deploy_bundle(project_name, paths, bundle_path, is_new,
                          no_snapshot, dry_run, component)


def _deploy_bundle(
    project_name: str, paths: BoxPaths, bundle_path: Path, is_new: bool,
    no_snapshot: bool, dry_run: bool, component: str,
) -> int:
    """Validate a bundle in .releases/incoming/, then install and start it.

    The live tree is only touched once every check has passed (audit C-01).
    On an upgrade the outgoing release and a snapshot of its data are kept
    for `rollback` (audit C-02).
    """
    new_ref = bundle_ref(bundle_path)
    snapshot_name = None
    try:
        with incoming_workspace(paths, project_name) as workspace:
            tree = extract_candidate(bundle_path, workspace)
            manifest = validate_release_tree(tree, project_name, paths, component)
            check_installable(tree, paths.project_dir(project_name))
            if dry_run:
                print(f"[DRY RUN] Bundle {bundle_path.name} is valid")
                print(f"[DRY RUN] Would install it and deploy '{project_name}'")
                return 0
            action = "Creating" if is_new else "Updating"
            print(f"{action} project '{project_name}' from {bundle_path.name}...")
            if not is_new:
                snapshot_name = snapshot_live_release(project_name, paths, no_snapshot)
                try:
                    keep_previous_release(paths, project_name, snapshot_name,
                                          new_ref, release_tree=tree)
                except (OSError, ReleaseStateError) as e:
                    return _install_failed(project_name, paths, e, changed=False,
                                           first_deploy=is_new)
            try:
                install_release(tree, paths.project_dir(project_name))
                mark_live(paths, project_name, new_ref)
            except (OSError, ValueError) as e:
                return _install_failed(project_name, paths, e, changed=True,
                                       first_deploy=is_new)
    except IntakeError as e:
        return report_refusal(e)

    register_project_identity(project_name, manifest.get("id", ""), paths)
    consume_bundle(bundle_path, project_name, paths)
    return _start_release(project_name, paths, manifest, new_ref,
                          snapshot_name, component)


def _install_failed(project_name: str, paths: BoxPaths, error: Exception,
                    changed: bool, first_deploy: bool) -> int:
    print(f"ERROR: Installing the release failed: {error}", file=sys.stderr)
    if changed and first_deploy:
        print("  The project files may be partly written. Fix the cause and "
              "deploy the bundle again.", file=sys.stderr)
    elif changed:
        print(f"  The project files may be partly updated. 'rollback "
              f"{project_name}' restores the previous release.", file=sys.stderr)
    else:
        print("  Nothing in the project was changed.", file=sys.stderr)
    log_error("deploy", f"Release install failed: {error}", paths, project=project_name)
    return 1


def _promote_staged(
    project_name: str, paths: BoxPaths, no_snapshot: bool, dry_run: bool,
    component: str,
) -> int:
    """Deploy the release `stage` installed; the production release it
    displaced becomes the previous release once the deploy succeeds."""
    if not has_prestage(paths, project_name):
        print(f"ERROR: No staged release is installed for '{project_name}'.",
              file=sys.stderr)
        return 1
    try:
        manifest = validate_release_tree(paths.project_dir(project_name),
                                         project_name, paths, component)
        staged_ref = live_ref(paths, project_name)
    except IntakeError as e:
        return report_refusal(e)
    except ReleaseStateError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    if dry_run:
        print(f"[DRY RUN] Would deploy the staged release {staged_ref}")
        return 0
    # Production data is snapshotted with the production release's own
    # backup config: that snapshot is what rollback pairs with it.
    snapshot_name = None
    try:
        if prestage_ref(paths, project_name) is not None:
            production = load_manifest(prestage_tree(paths, project_name) / "manifest.yml")
            snapshot_name = take_pre_deploy_snapshot(project_name, paths, production,
                                                     no_snapshot)
    except (ManifestError, ReleaseStateError) as e:
        print(f"ERROR: Cannot read the kept production release: {e}", file=sys.stderr)
        return 1
    rc = _start_release(project_name, paths, manifest, staged_ref,
                        snapshot_name, component)
    if rc != 0:
        # Production still runs the kept release: check it with its own scripts.
        sync_live_scripts(paths, project_name, prestage_tree(paths, project_name))
        return rc
    try:
        prestage_to_previous(paths, project_name, snapshot_name, staged_ref)
    except (OSError, ReleaseStateError) as e:
        print(f"ERROR: {staged_ref} is live, but keeping the release it "
              f"replaced failed: {e}. 'rollback {project_name}' is not "
              f"available for this deploy.", file=sys.stderr)
        log_error("deploy", f"Keeping the previous release failed: {e}",
                  paths, project=project_name)
        # Production now runs the staged release. A kept production release
        # left behind would let unstage put old files under it, and an older
        # previous release would pair the wrong code with the data: drop both.
        try:
            discard_prestage(paths, project_name)
            discard_previous_release(paths, project_name)
        except OSError as cleanup_error:
            print(f"ERROR: Could not remove .releases/prestage/: {cleanup_error}. "
                  f"Remove it by hand before running 'unstage {project_name}'.",
                  file=sys.stderr)
        return 1
    return 0


def redeploy_installed(
    project_name: str,
    paths: BoxPaths,
    ref: str | None,
    no_snapshot: bool,
    dry_run: bool,
    component: str,
) -> int:
    """Validate and start the bundle release already in the project dir.

    `ref` labels the release in deploy state; None keeps the installed
    release's own ref. Caller holds the project lock.
    """
    project_dir = paths.project_dir(project_name)
    if not project_dir.exists():
        print(f"ERROR: Project not found: {project_dir}", file=sys.stderr)
        return 1
    try:
        manifest = validate_release_tree(project_dir, project_name, paths, component)
        actual_ref = ref or live_ref(paths, project_name)
    except IntakeError as e:
        return report_refusal(e)
    except ReleaseStateError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    if dry_run:
        print(f"[DRY RUN] Would redeploy {project_name} (ref: {actual_ref})")
        return 0
    snapshot_name = take_pre_deploy_snapshot(project_name, paths, manifest, no_snapshot)
    return _start_release(project_name, paths, manifest, actual_ref,
                          snapshot_name, component)


def _deploy_repo(
    project_name: str, paths: BoxPaths, ref: str | None,
    no_snapshot: bool, dry_run: bool, component: str,
) -> int:
    """Check out the requested ref of a git-sourced project and start it."""
    repo_dir = paths.project_dir(project_name) / "repo"
    try:
        manifest = load_manifest(paths.project_manifest(project_name))
    except ManifestError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    deploy_ref = ref or manifest.get("ref", "main")
    if dry_run:
        print(f"[DRY RUN] Would deploy {project_name} at ref {deploy_ref}")
        return 0
    actual_ref = update_repo(repo_dir, deploy_ref, manifest)
    if actual_ref is None:
        return 1
    try:
        manifest = validate_release_tree(paths.project_dir(project_name),
                                         project_name, paths, component)
    except IntakeError as e:
        return report_refusal(e)
    snapshot_name = take_pre_deploy_snapshot(project_name, paths, manifest, no_snapshot)
    return _start_release(project_name, paths, manifest, actual_ref,
                          snapshot_name, component)


def _start_release(
    project_name: str,
    paths: BoxPaths,
    manifest: dict,
    actual_ref: str,
    snapshot_name: str | None,
    component: str,
) -> int:
    """Run pre-deploy, generate config, start, smoke-test, record.

    The release on disk has already passed validate_release_tree and its
    pre-deploy snapshot (if any) has been taken.
    """
    project_dir = paths.project_dir(project_name)
    print(f"Deploying {project_name} (ref: {actual_ref})...")

    pre_deploy = manifest.get("deploy", {}).get("pre_deploy", "")
    if pre_deploy:
        print(f"  Running pre-deploy: {pre_deploy}")
        try:
            subprocess.run(
                shlex.split(pre_deploy), shell=False, cwd=project_dir, check=True,
                capture_output=True, text=True,
            )
        except subprocess.CalledProcessError as e:
            print(f"  ERROR: Pre-deploy failed: {e.stderr}", file=sys.stderr)
            return 1

    print("  Generating Caddy config...")
    prepare_caddy_config(paths, manifest)

    print("  Generating compose overlay...")
    prepare_compose_override(paths, manifest, component=component,
                             release_root=project_dir)

    print("  Starting containers...")
    compose_files = ["compose.yml", "compose.boxmunge.yml"]
    try:
        compose_up(project_dir, compose_files=compose_files,
                   project_name=project_name)
    except DockerError as e:
        print(f"  ERROR: {e}", file=sys.stderr)
        log_error("deploy", f"Deploy failed: container start: {e}", paths, project=project_name)
        return 1

    post_deploy_diagnostics(project_name, paths, project_dir, manifest)

    print("  Reloading Caddy...")
    try:
        caddy_reload(paths.caddy, paths.state)
    except CaddyConfigRejected as e:
        return _caddy_rejected(project_name, paths, e)
    except DockerError as e:
        print(f"  WARN: Caddy reload failed: {e}")

    if not smoke_ok(project_name, paths, project_dir, manifest, compose_files):
        return 1

    record_deploy_state(paths, project_name, actual_ref, snapshot_name)

    log_operation("deploy", f"Deploy completed ref={actual_ref}", paths,
                  project=project_name, detail={"ref": actual_ref})
    print(f"{project_name}: deployed successfully (ref: {actual_ref})")

    from boxmunge.webhooks import webhook_safe
    webhook_safe("deploy", project_name, paths, details={"ref": actual_ref})

    return 0


def _caddy_rejected(project_name: str, paths: BoxPaths,
                    error: CaddyConfigRejected) -> int:
    """Caddy refused the new site config: fail, and say where things stand."""
    site = paths.project_caddy_site(project_name).name
    restored = ", ".join(error.restored) or "(nothing journaled)"
    print(f"ERROR: Caddy rejected the new site config ({site}); the previous "
          f"routing was restored for: {restored}.", file=sys.stderr)
    print(f"  The new release's containers are running behind the previous "
          f"routing. Fix the site config and deploy again"
          + (f", or run 'rollback {project_name}' to return to the previous "
             f"release." if _has_rollback_target(paths, project_name) else "."),
          file=sys.stderr)
    log_error("deploy", f"Caddy rejected {site}; previous routing restored",
              paths, project=project_name)
    return 1


def _has_rollback_target(paths: BoxPaths, project_name: str) -> bool:
    if (paths.project_dir(project_name) / "repo").exists():
        return bool(read_state(paths.project_deploy_state(project_name)).get("history"))
    return previous_dir(paths, project_name).is_dir()


def run_deploy(
    project_name: str,
    paths: BoxPaths,
    ref: str | None = None,
    no_snapshot: bool = False,
    dry_run: bool = False,
    _lock_held: bool = False,
    component: str = "deploy",
    staged: bool = False,
) -> int:
    """Execute the full deploy flow. Returns 0 on success, 1 on failure,
    3 for a compose hardening rejection.

    `component` labels the SECURITY OFF log entry so promote/rollback callers
    can attribute the warning to the correct CLI verb (default: "deploy").
    `staged=True` (promote) deploys the release `stage` installed instead of
    taking one from the inbox.
    """
    block = is_blocked(project_name, paths)
    if block:
        print(f"ERROR: {block.refuse_message}", file=sys.stderr)
        return 1
    clear_probation_if_active(paths, "deploy")
    from boxmunge.project_registry import is_registered
    if not is_registered(project_name, paths):
        print(f"ERROR: Project '{project_name}' is not registered on this server. "
              f"Run: project-add {project_name}", file=sys.stderr)
        return 1

    if not _lock_held:
        try:
            with project_lock(project_name, paths):
                return _run_deploy_inner(
                    project_name, paths, ref, no_snapshot, dry_run,
                    component=component, staged=staged,
                )
        except LockError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
    return _run_deploy_inner(
        project_name, paths, ref, no_snapshot, dry_run, component=component,
        staged=staged,
    )


def cmd_deploy(args: list[str]) -> None:
    """CLI entry point for prod-deploy command."""
    from boxmunge.commands.argv import parse_args, require_project_name
    parsed = parse_args(
        "prod-deploy", args, flags={"--no-snapshot", "--dry-run"},
        options={"--ref"}, min_positional=1, max_positional=1,
    )
    project = require_project_name("prod-deploy", parsed.positional[0])
    sys.exit(run_deploy(project, BoxPaths(), ref=parsed.get("--ref"),
                        no_snapshot=parsed.has("--no-snapshot"),
                        dry_run=parsed.has("--dry-run")))
