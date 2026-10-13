# SPDX-License-Identifier: Apache-2.0
"""boxmunge prod-deploy <project> — full deployment flow."""

import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from boxmunge.bundle import copy_project_files
from boxmunge.caddy import prepare_caddy_config
from boxmunge.compose import prepare_compose_override
from boxmunge.docker import compose_up, caddy_reload, DockerError
from boxmunge.fileutil import project_lock, LockError
from boxmunge.identity import register_project_identity
from boxmunge.intake import (
    IntakeError, extract_candidate, incoming_workspace, report_refusal,
    validate_release_tree,
)
from boxmunge.lifecycle import is_blocked
from boxmunge.log import log_operation, log_error, log_warning
from boxmunge.manifest import load_manifest, ManifestError
from boxmunge.paths import BoxPaths
from boxmunge.probation import clear_probation_if_active
from boxmunge.source import (
    SourceError, bundle_ref, consume_bundle, resolve_bundle_source,
)
from boxmunge.state import read_state, write_state


def record_deploy_state(
    paths: BoxPaths,
    project_name: str,
    ref: str,
    snapshot: str | None,
) -> None:
    """Record a deploy in the state file, pushing previous to history."""
    state_path = paths.project_deploy_state(project_name)
    current = read_state(state_path)

    history = current.get("history", [])
    if "current_ref" in current:
        history.insert(0, {
            "ref": current["current_ref"],
            "deployed_at": current.get("deployed_at", ""),
            "snapshot": current.get("pre_deploy_snapshot", ""),
        })
        history = history[:10]

    now_iso = datetime.now(timezone.utc).isoformat()
    new_state = {
        "current_ref": ref,
        "deployed_at": now_iso,
        # Drives the health-check grace window in health_state.update_health_state.
        # Updated on resume too; spurious mid-startup smoke flakes get masked.
        "last_started_at": now_iso,
        "pre_deploy_snapshot": snapshot or "",
        "history": history,
    }

    write_state(state_path, new_state)


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
        return _deploy_on_disk(project_name, paths, ref, no_snapshot,
                               dry_run, component)

    try:
        bundle_path = resolve_bundle_source(project_name, paths, ref=ref)
    except SourceError as e:
        if is_new:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        print(f"No new bundle for '{project_name}' in the inbox; "
              f"redeploying the release already on disk.")
        return _deploy_on_disk(project_name, paths, None, no_snapshot,
                               dry_run, component)

    # Unpack and validate in .releases/incoming/; the live tree is only
    # touched once every check has passed (audit C-01).
    try:
        with incoming_workspace(paths, project_name) as workspace:
            tree = extract_candidate(bundle_path, workspace)
            manifest = validate_release_tree(tree, project_name, paths, component)
            if dry_run:
                print(f"[DRY RUN] Bundle {bundle_path.name} is valid")
                print(f"[DRY RUN] Would install it and deploy '{project_name}'")
                return 0
            action = "Creating" if is_new else "Updating"
            print(f"{action} project '{project_name}' from {bundle_path.name}...")
            project_dir.mkdir(parents=True, exist_ok=True)
            copy_project_files(tree, project_dir, is_upgrade=not is_new)
    except IntakeError as e:
        return report_refusal(e)

    register_project_identity(project_name, manifest.get("id", ""), paths)
    consume_bundle(bundle_path, paths)
    return _start_release(project_name, paths, manifest,
                          bundle_ref(bundle_path), no_snapshot, component)


def _deploy_on_disk(
    project_name: str,
    paths: BoxPaths,
    ref: str | None,
    no_snapshot: bool,
    dry_run: bool,
    component: str,
) -> int:
    """Deploy the code already in the project dir (pulling first for git)."""
    project_dir = paths.project_dir(project_name)
    repo_dir = project_dir / "repo"
    if repo_dir.exists():
        try:
            manifest = load_manifest(paths.project_manifest(project_name))
        except ManifestError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        deploy_ref = ref or manifest.get("ref", "main")
        if dry_run:
            print(f"[DRY RUN] Would deploy {project_name} at ref {deploy_ref}")
            return 0
        actual_ref = _git_update(repo_dir, deploy_ref, manifest)
        if actual_ref is None:
            return 1
    else:
        current = read_state(paths.project_deploy_state(project_name))
        actual_ref = current.get("current_ref", "on-disk")

    try:
        manifest = validate_release_tree(project_dir, project_name, paths, component)
    except IntakeError as e:
        return report_refusal(e)

    if dry_run:
        print(f"[DRY RUN] Would redeploy {project_name} (ref: {actual_ref})")
        return 0
    return _start_release(project_name, paths, manifest, actual_ref,
                          no_snapshot, component)


def _git_update(repo_dir: Path, deploy_ref: str, manifest: dict) -> str | None:
    """Fetch and check out deploy_ref; return the short HEAD sha, None on error."""
    if manifest.get("repo", ""):
        print(f"  Pulling {deploy_ref}...")
        try:
            subprocess.run(
                ["git", "fetch", "origin"], cwd=repo_dir, check=True,
                capture_output=True, text=True,
            )
            subprocess.run(
                ["git", "checkout", deploy_ref], cwd=repo_dir, check=True,
                capture_output=True, text=True,
            )
            subprocess.run(
                ["git", "pull", "--ff-only", "origin", deploy_ref],
                cwd=repo_dir, check=False, capture_output=True, text=True,
            )
        except subprocess.CalledProcessError as e:
            print(f"  ERROR: Git pull failed: {e.stderr}", file=sys.stderr)
            return None
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=repo_dir, capture_output=True, text=True, check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"  ERROR: Cannot read the deployed git ref: {e}", file=sys.stderr)
        return None
    return result.stdout.strip()


def _take_pre_deploy_snapshot(
    project_name: str, paths: BoxPaths, manifest: dict, no_snapshot: bool,
) -> str | None:
    """Back up project data before the new release starts. Returns its name."""
    snapshot_enabled = manifest.get("deploy", {}).get("snapshot_before_deploy", True)
    backup_type = manifest.get("backup", {}).get("type", "none")
    if not snapshot_enabled or no_snapshot or backup_type == "none":
        return None
    print("  Taking pre-deploy snapshot...")
    from boxmunge.backup import BackupKind
    from boxmunge.commands.backup_cmd import list_snapshots, run_backup
    if run_backup(project_name, paths, _lock_held=True,
                  kind=BackupKind.PREDEPLOY) != 0:
        print("  WARN: Pre-deploy backup failed — continuing deploy")
        return None
    snaps = list_snapshots(paths, project_name)
    return snaps[0].name if snaps else None


def _start_release(
    project_name: str,
    paths: BoxPaths,
    manifest: dict,
    actual_ref: str,
    no_snapshot: bool,
    component: str,
) -> int:
    """Snapshot, run pre-deploy, generate config, start, smoke-test, record.

    The release on disk has already passed validate_release_tree.
    """
    project_dir = paths.project_dir(project_name)
    print(f"Deploying {project_name} (ref: {actual_ref})...")

    snapshot_name = _take_pre_deploy_snapshot(project_name, paths, manifest, no_snapshot)

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
    prepare_compose_override(paths, manifest, component=component)

    print("  Starting containers...")
    compose_files = ["compose.yml", "compose.boxmunge.yml"]
    try:
        compose_up(project_dir, compose_files=compose_files)
    except DockerError as e:
        print(f"  ERROR: {e}", file=sys.stderr)
        log_error("deploy", f"Deploy failed: container start: {e}", paths, project=project_name)
        return 1

    _post_deploy_diagnostics(project_name, paths, project_dir, manifest)

    print("  Reloading Caddy...")
    try:
        caddy_reload(paths.caddy, paths.state)
    except DockerError as e:
        print(f"  WARN: Caddy reload failed: {e}")

    if not _smoke_ok(project_name, paths, project_dir, manifest, compose_files):
        return 1

    record_deploy_state(paths, project_name, actual_ref, snapshot_name)

    log_operation("deploy", f"Deploy completed ref={actual_ref}", paths,
                  project=project_name, detail={"ref": actual_ref})
    print(f"{project_name}: deployed successfully (ref: {actual_ref})")

    from boxmunge.webhooks import webhook_safe
    webhook_safe("deploy", project_name, paths, details={"ref": actual_ref})

    return 0


def _post_deploy_diagnostics(
    project_name: str, paths: BoxPaths, project_dir: Path, manifest: dict,
) -> None:
    """v0.9: 8-second post-up scan for read-only-fs errors.

    Best-effort by design: the goal is operator visibility, not gating. Hints
    point operators at services.<svc>.writable.ephemeral when a missing
    declaration crashes the container. Failures are logged, never raised.
    """
    try:
        from boxmunge.writable_diagnostics import run_post_deploy_diagnostics
        hints = run_post_deploy_diagnostics(project_dir, manifest)
        for svc_name, hint in hints.items():
            print(hint)
            log_warning(
                "deploy",
                f"writable-fs error detected in {svc_name}",
                paths, project=project_name,
                detail={"event": "writable_diagnostic", "service": svc_name},
            )
    except Exception as e:
        log_warning(
            "deploy", f"writable diagnostics raised: {e}",
            paths, project=project_name,
        )


def _smoke_ok(
    project_name: str, paths: BoxPaths, project_dir: Path, manifest: dict,
    compose_files: list[str],
) -> bool:
    """Run per-service smoke tests inside the containers. False on failure."""
    has_smoke = any(svc.get("smoke") for svc in manifest.get("services", {}).values())
    if not has_smoke:
        return True
    print("  Running smoke tests in containers...")
    from boxmunge.commands.check import run_smoke_in_container, should_downgrade_smoke_failure
    smoke_result = run_smoke_in_container(project_dir, manifest, compose_files)
    if smoke_result.status == "ok":
        print("  Smoke tests passed.")
        return True
    if should_downgrade_smoke_failure(project_name, paths):
        print(f"  WARN: Smoke test {smoke_result.status} (first deploy — "
              f"downgraded to warning): {smoke_result.message}")
        log_warning("deploy", f"First deploy smoke {smoke_result.status} "
                    f"downgraded: {smoke_result.message}",
                    paths, project=project_name)
        return True
    print(f"  ERROR: Smoke test {smoke_result.status}: {smoke_result.message}",
          file=sys.stderr)
    log_error("deploy", f"Smoke test {smoke_result.status}: {smoke_result.message}",
              paths, project=project_name)
    return False


def run_deploy(
    project_name: str,
    paths: BoxPaths,
    ref: str | None = None,
    no_snapshot: bool = False,
    dry_run: bool = False,
    _lock_held: bool = False,
    component: str = "deploy",
) -> int:
    """Execute the full deploy flow. Returns 0 on success, 1 on failure.

    `component` labels the SECURITY OFF log entry so promote/rollback callers
    can attribute the warning to the correct CLI verb (default: "deploy").
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
                    component=component,
                )
        except LockError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
    return _run_deploy_inner(
        project_name, paths, ref, no_snapshot, dry_run, component=component,
    )


def cmd_deploy(args: list[str]) -> None:
    """CLI entry point for prod-deploy command."""
    if not args:
        print("Usage: prod-deploy <project> [--ref REF] [--no-snapshot] [--dry-run]",
              file=sys.stderr)
        sys.exit(2)

    project = args[0]

    from boxmunge.paths import validate_project_name
    try:
        validate_project_name(project)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)

    ref = None
    no_snapshot = False
    dry_run = False

    remaining = args[1:]
    i = 0
    while i < len(remaining):
        if remaining[i] == "--ref" and i + 1 < len(remaining):
            ref = remaining[i + 1]
            i += 2
        elif remaining[i] == "--no-snapshot":
            no_snapshot = True
            i += 1
        elif remaining[i] == "--dry-run":
            dry_run = True
            i += 1
        else:
            print(f"ERROR: unknown argument: {remaining[i]}", file=sys.stderr)
            sys.exit(2)

    paths = BoxPaths()
    exit_code = run_deploy(project, paths, ref=ref, no_snapshot=no_snapshot,
                           dry_run=dry_run)
    sys.exit(exit_code)
