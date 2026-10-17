# SPDX-License-Identifier: Apache-2.0
"""boxmunge prod-deploy <project> — full deployment flow."""

import shlex
import subprocess
import sys
from pathlib import Path

from boxmunge.bind_sources import BindSourceError
from boxmunge.commands import deploy_storage
from boxmunge.commands.release_config import (
    decide_release_users, generate_release_config, promote_candidates,
)
from boxmunge.commands.deploy_steps import (
    post_deploy_diagnostics, record_deploy_state, smoke_ok, take_pre_deploy_snapshot,
)
from boxmunge.compose import ComposeError
from boxmunge.compose_guard import compose_up_checked
from boxmunge.compose_resolve import ComposeResolveError
from boxmunge.docker import CaddyConfigRejected, caddy_reload, DockerError
from boxmunge.fileutil import project_lock, LockError
from boxmunge.identity import register_project_identity
from boxmunge.intake import (
    IntakeError, check_installable, extract_candidate, incoming_workspace,
    report_refusal, validate_release_tree,
)
from boxmunge.lifecycle import refuse_if_blocked
from boxmunge.legacy_stage import refuse_if_legacy_stage
from boxmunge.log import log_operation, log_error
from boxmunge.manifest import load_manifest, ManifestError
from boxmunge.paths import BoxPaths
from boxmunge.probation import clear_probation_if_active
from boxmunge.release import ReleaseStateError, live_ref, previous_dir
from boxmunge.release_target import DeployRefused, production_target
from boxmunge.run_as import RunAsError
from boxmunge.userns.offset import RemapError
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

    # Git projects have a repo/ dir and check a commit out in place. Bundle
    # projects take a release from the inbox.
    if not is_new and (project_dir / "repo").exists():
        return _deploy_repo(project_name, paths, ref, no_snapshot, dry_run, component)

    try:
        bundle_path = resolve_bundle_source(project_name, paths, ref=ref)
    except SourceError as e:
        from boxmunge.commands.deploy_tree import resume_without_bundle
        from boxmunge.release_txn import load_txn
        try:
            txn = load_txn(paths, project_name)
        except ReleaseStateError as err:
            print(f"ERROR: {err}", file=sys.stderr)
            return 1
        if txn is not None and dry_run:
            from boxmunge.commands.deploy_tree import bundle_resume_problem
            problem = bundle_resume_problem(project_name, paths, txn, ref)
            if problem:
                print(f"ERROR: {problem}.", file=sys.stderr)
                return 1
            print(f"[DRY RUN] Would resume the open install of {txn.ref} "
                  f"(phase {txn.phase}) from the project dir")
            return 0
        if txn is not None:
            return resume_without_bundle(project_name, paths, txn, ref, component)
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
    """Fetch origin, resolve the ref (--ref, else the live manifest's) to a
    full SHA, and deploy exactly that commit (commands/git_deploy.py)."""
    from boxmunge.commands.git_deploy import GitDeploy, deploy_git_locked
    from boxmunge.git_slot import (
        GitRefError, fetch, require_regular_control_files, resolve_ref,
    )
    repo_dir = paths.project_dir(project_name) / "repo"
    try:
        wanted = ref or load_manifest(paths.project_manifest(project_name)).get("ref", "main")
        print(f"  Fetching {wanted}...")
        fetch(repo_dir)
        sha = resolve_ref(repo_dir, wanted)
        require_regular_control_files(repo_dir, sha)
    except (ManifestError, GitRefError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    if dry_run:
        print(f"[DRY RUN] Would deploy {project_name} at {wanted} ({sha})")
        return 0
    return deploy_git_locked(project_name, paths, GitDeploy(
        sha=sha, source="git", component=component, no_snapshot=no_snapshot))


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
    print(f"Deploying {project_name} (ref: {actual_ref})...")
    try:
        users = decide_release_users(project_name, paths, manifest, component)
    except (DeployRefused, DockerError) as e:
        print(f"ERROR: {project_name} cannot start as it is; nothing was run or changed "
              f"(production runs its previous containers). Fix the following and deploy "
              f"again:\n{e}", file=sys.stderr)
        log_error(component, f"Deploy refused before the start: {e}", paths,
                  project=project_name)
        return 1
    rc = run_pre_deploy_hook(project_name, paths, manifest)
    if rc != 0:
        return rc
    try:
        generate_release_config(project_name, paths, manifest, component, users)
    except (OSError, ValueError) as e:
        print(f"ERROR: {project_name} was not started: production still runs its "
              f"previous containers. Fix the following and deploy again:\n{e}",
              file=sys.stderr)
        log_error(component, f"Deploy refused before the start: {e}", paths,
                  project=project_name)
        return 1
    return replace_release(project_name, paths, manifest, actual_ref, snapshot_name,
                           component=component)


def run_pre_deploy_hook(project_name: str, paths: BoxPaths, manifest: dict) -> int:
    """The manifest's pre-deploy command. Production is not touched yet.

    It runs on the host in the project directory, split into words but with
    no shell, so `&&`, pipes and `$VAR` reach the program as arguments. It
    is project code, so it runs as deploy in the deploy shell's environment,
    also when an operator deploys with sudo (as_deploy).
    """
    from boxmunge.as_deploy import NoDeployUser, run_as_deploy
    from boxmunge.manifest_fields import deploy_problems
    deploy = manifest.get("deploy", {})
    problems = deploy_problems(deploy)
    if problems:  # validated on deploy; a release kept from before may not be
        print(f"  ERROR: {problems[0]}", file=sys.stderr)
        return 1
    pre_deploy = deploy.get("pre_deploy")
    if not pre_deploy:
        return 0
    project_dir = paths.project_dir(project_name)
    if not project_dir.is_dir():
        print(f"  ERROR: Pre-deploy cannot run: the project directory {project_dir} "
              "does not exist.", file=sys.stderr)
        return 1
    print(f"  Running pre-deploy: {pre_deploy}")
    try:
        run_as_deploy(shlex.split(pre_deploy), project_dir, supplementary_groups=True)
    except NoDeployUser as e:
        print(f"  ERROR: Pre-deploy not run: {e}. Create the deploy user (install.sh "
              "does), or deploy as deploy through its shell.", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as e:
        print(f"  ERROR: Pre-deploy failed: {e.stderr}", file=sys.stderr)
        return 1
    except OSError as e:
        reason = "not found" if isinstance(e, FileNotFoundError) else (
            "not executable" if isinstance(e, PermissionError) else e.strerror)
        print(f"  ERROR: Pre-deploy command cannot run: {e.filename}: {reason}. "
              "deploy.pre_deploy runs without a shell, from the project directory: "
              "name an executable on the host's PATH, or a script in the project "
              "(mode 0755) for anything with more than one step.", file=sys.stderr)
        return 1
    return 0


def replace_release(project_name: str, paths: BoxPaths, manifest: dict,
                    actual_ref: str, snapshot_name: str | None,
                    component: str = "deploy", txn: str | None = None,
                    replaced_ref: str | None = None) -> int:
    """Start the release in production, route it, smoke-test, record.

    From the container start on, production runs (or partly runs) this
    release whatever fails afterwards, so the deploy state records it
    either way: the release it replaced becomes the rollback target, paired
    with the snapshot taken before this deploy. Only a first deploy that
    fails records nothing, so a retry is still treated as a first deploy.

    `txn` is the id of the install transaction this start finishes
    (release_txn), and `replaced_ref` the release it replaced (the
    rollback target; see record_deploy_state).
    """
    first_deploy = "current_ref" not in read_state(paths.project_deploy_state(project_name))
    rc = 1
    try:
        rc = _start_and_verify(project_name, paths, manifest, component, txn)
    finally:
        if rc == 0 or not first_deploy:
            record_deploy_state(paths, project_name, actual_ref, snapshot_name, replaced_ref)
    if rc != 0:
        return rc

    log_operation("deploy", f"Deploy completed ref={actual_ref}", paths,
                  project=project_name, detail={"ref": actual_ref})
    print(f"{project_name}: deployed successfully (ref: {actual_ref})")

    from boxmunge.webhooks import webhook_safe
    webhook_safe("deploy", project_name, paths, details={"ref": actual_ref})
    return 0


def _start_and_verify(project_name: str, paths: BoxPaths, manifest: dict,
                      component: str = "deploy", txn: str | None = None) -> int:
    project_dir = paths.project_dir(project_name)
    print("  Starting containers...")
    compose_files = ["compose.yml", "compose.boxmunge.yml"]
    try:
        promote_candidates(paths, project_name)
        deploy_storage.prepare_storage(paths, production_target(paths, project_name))
        # generate_release_config built every image the users were decided from.
        compose_up_checked(paths, project_name, component=component,
                           compose_files=compose_files, record=True, deploying=True,
                           build=False, txn=txn)
    except (DockerError, BindSourceError, RunAsError, ComposeResolveError, RemapError,
            ComposeError, OSError) as e:
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
    if refuse_if_blocked(project_name, paths) or refuse_if_legacy_stage(paths, project_name):
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
    from boxmunge.commands.argv import parse_args, require_project_name, usage_error
    parsed = parse_args(
        "prod-deploy", args, flags={"--no-snapshot", "--dry-run", "--abandon"},
        options={"--ref"}, min_positional=1, max_positional=1,
    )
    project = require_project_name("prod-deploy", parsed.positional[0])
    if parsed.has("--abandon"):
        if parsed.get("--ref") or parsed.has("--no-snapshot") or parsed.has("--dry-run"):
            usage_error("prod-deploy", "--abandon takes no other options")
        from boxmunge.commands import install_abandon
        sys.exit(install_abandon.run_abandon(project, BoxPaths()))
    sys.exit(run_deploy(project, BoxPaths(), ref=parsed.get("--ref"),
                        no_snapshot=parsed.has("--no-snapshot"),
                        dry_run=parsed.has("--dry-run")))
