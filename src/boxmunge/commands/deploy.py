# SPDX-License-Identifier: Apache-2.0
"""boxmunge prod-deploy <project> — full deployment flow."""

import shlex
import subprocess
import sys
from pathlib import Path

from boxmunge.caddy import prepare_caddy_config
from boxmunge.commands.deploy_steps import (
    post_deploy_diagnostics, record_deploy_state, smoke_ok, take_pre_deploy_snapshot,
    update_repo,
)
from boxmunge.compose import prepare_compose_override
from boxmunge.compose_guard import compose_up_checked
from boxmunge.docker import CaddyConfigRejected, caddy_reload, DockerError
from boxmunge.fileutil import project_lock, LockError
from boxmunge.identity import register_project_identity
from boxmunge.intake import (
    IntakeError, check_installable, extract_candidate, incoming_workspace,
    report_refusal, validate_release_tree,
)
from boxmunge.lifecycle import refuse_if_blocked
from boxmunge.log import log_operation, log_error
from boxmunge.manifest import load_manifest, ManifestError
from boxmunge.paths import BoxPaths
from boxmunge.probation import clear_probation_if_active
from boxmunge.release import ReleaseStateError, live_ref, previous_dir
from boxmunge.release_staging import has_prestage
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
) -> int:
    """Inner deploy logic — caller must hold the project lock."""
    project_dir = paths.project_dir(project_name)
    is_new = not (project_dir / "manifest.yml").exists()

    # Git projects have a repo/ dir and pull their code in place. Bundle
    # projects take a release from the inbox.
    if not is_new and (project_dir / "repo").exists():
        return _deploy_repo(project_name, paths, ref, no_snapshot, dry_run, component)

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
    """Validate a bundle in .releases/incoming/, then install and start it
    inside an install transaction (commands/deploy_tree.py)."""
    from boxmunge.commands.deploy_tree import TreeDeploy, deploy_tree_locked
    new_ref = bundle_ref(bundle_path)
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

            def installed() -> None:
                register_project_identity(project_name, manifest.get("id", ""), paths)
                consume_bundle(bundle_path, project_name, paths)

            return deploy_tree_locked(project_name, paths, TreeDeploy(
                tree=tree, ref=new_ref, source="bundle", manifest=manifest,
                component=component, no_snapshot=no_snapshot, on_installed=installed))
    except IntakeError as e:
        return report_refusal(e)


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
    promoting: bool = False,
) -> int:
    """Run pre-deploy, generate config, start, smoke-test, record.

    The release on disk has already passed validate_release_tree and its
    pre-deploy snapshot (if any) has been taken. `promoting`: it is the
    staged release, which production may start from while it is staged.
    """
    print(f"Deploying {project_name} (ref: {actual_ref})...")
    rc = run_pre_deploy_hook(project_name, paths, manifest)
    if rc != 0:
        return rc
    generate_release_config(project_name, paths, manifest, component)
    return replace_release(project_name, paths, manifest, actual_ref, snapshot_name,
                           component=component, promoting=promoting)


def run_pre_deploy_hook(project_name: str, paths: BoxPaths, manifest: dict) -> int:
    """The manifest's pre-deploy command. Production is not touched yet."""
    pre_deploy = manifest.get("deploy", {}).get("pre_deploy", "")
    if not pre_deploy:
        return 0
    print(f"  Running pre-deploy: {pre_deploy}")
    try:
        subprocess.run(
            shlex.split(pre_deploy), shell=False, cwd=paths.project_dir(project_name),
            check=True, capture_output=True, text=True,
        )
    except subprocess.CalledProcessError as e:
        print(f"  ERROR: Pre-deploy failed: {e.stderr}", file=sys.stderr)
        return 1
    return 0


def generate_release_config(project_name: str, paths: BoxPaths, manifest: dict,
                            component: str) -> None:
    """Write the release's Caddy site and compose overlay (not yet live)."""
    print("  Generating Caddy config...")
    prepare_caddy_config(paths, manifest)
    print("  Generating compose overlay...")
    prepare_compose_override(paths, manifest, component=component,
                             release_root=paths.project_dir(project_name))


def replace_release(project_name: str, paths: BoxPaths, manifest: dict,
                    actual_ref: str, snapshot_name: str | None,
                    component: str = "deploy", promoting: bool = False,
                    txn: str | None = None) -> int:
    """Start the release in production, route it, smoke-test, record.

    From the container start on, production runs (or partly runs) this
    release whatever fails afterwards, so the deploy state records it
    either way: the release it replaced becomes the rollback target, paired
    with the snapshot taken before this deploy. Only a first deploy that
    fails records nothing, so a retry is still treated as a first deploy.

    `promoting` is true when the release is the staged one a `promote`
    deploys: production may start from it even while it is staged. `txn`
    is the id of the install transaction this start finishes (release_txn).
    """
    first_deploy = "current_ref" not in read_state(paths.project_deploy_state(project_name))
    rc = 1
    try:
        rc = _start_and_verify(project_name, paths, manifest, component, promoting, txn)
    finally:
        if rc == 0 or not first_deploy:
            record_deploy_state(paths, project_name, actual_ref, snapshot_name)
    if rc != 0:
        return rc

    log_operation("deploy", f"Deploy completed ref={actual_ref}", paths,
                  project=project_name, detail={"ref": actual_ref})
    print(f"{project_name}: deployed successfully (ref: {actual_ref})")

    from boxmunge.webhooks import webhook_safe
    webhook_safe("deploy", project_name, paths, details={"ref": actual_ref})
    return 0


def _start_and_verify(project_name: str, paths: BoxPaths, manifest: dict,
                      component: str = "deploy", promoting: bool = False,
                      txn: str | None = None) -> int:
    project_dir = paths.project_dir(project_name)
    print("  Starting containers...")
    compose_files = ["compose.yml", "compose.boxmunge.yml"]
    try:
        compose_up_checked(paths, project_name, component=component,
                           compose_files=compose_files, record=True, promoting=promoting,
                           deploying=True, txn=txn)
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
    if error.refused:
        print(f"ERROR: some site files were not restored: {error.refused}",
              file=sys.stderr)
    log_error("deploy", f"Caddy rejected {site}; previous routing restored for: "
              f"{restored}" + (f"; refused: {error.refused}" if error.refused else ""),
              paths, project=project_name)
    return 1


def _has_rollback_target(paths: BoxPaths, project_name: str) -> bool:
    if (paths.project_dir(project_name) / "repo").exists():
        return bool(read_state(paths.project_deploy_state(project_name)).get("history"))
    return previous_dir(paths, project_name).is_dir()


def deploy_eligible(project_name: str, paths: BoxPaths) -> bool:
    """Checked by every deploy core under the project lock, immediately
    before anything changes. Prints why and returns False if not."""
    if refuse_if_blocked(project_name, paths):
        return False
    from boxmunge.project_registry import is_registered
    if not is_registered(project_name, paths):
        print(f"ERROR: Project '{project_name}' is not registered on this server. "
              f"Run: project-add {project_name}", file=sys.stderr)
        return False
    return True


def deploy_locked(
    project_name: str,
    paths: BoxPaths,
    ref: str | None = None,
    no_snapshot: bool = False,
    dry_run: bool = False,
    component: str = "deploy",
) -> int:
    """The deploy core. Caller holds the project lock; never takes it.

    `component` labels log entries for the CLI verb that asked (promote,
    rollback).
    """
    if not deploy_eligible(project_name, paths):
        return 1
    clear_probation_if_active(paths, "deploy")
    return _run_deploy_inner(
        project_name, paths, ref, no_snapshot, dry_run, component=component,
    )


def run_deploy(
    project_name: str,
    paths: BoxPaths,
    ref: str | None = None,
    no_snapshot: bool = False,
    dry_run: bool = False,
) -> int:
    """prod-deploy: take the project lock and deploy. Returns 0 on success,
    1 on failure, 3 for a compose hardening rejection."""
    try:
        with project_lock(project_name, paths):
            return deploy_locked(project_name, paths, ref, no_snapshot, dry_run)
    except LockError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


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
