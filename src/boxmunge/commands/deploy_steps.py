# SPDX-License-Identifier: Apache-2.0
"""Individual deploy steps: snapshot, repo update, diagnostics, smoke, state."""

import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from boxmunge.log import log_error, log_warning
from boxmunge.manifest import ManifestError, load_manifest
from boxmunge.paths import BoxPaths
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
    # Merge, never rebuild: other writers keep keys here too, notably
    # project_id, which the name/ULID collision guard reads (audit C-08).
    new_state = {
        **current,
        "current_ref": ref,
        "deployed_at": now_iso,
        # Drives the health-check grace window in health_state.update_health_state.
        # Updated on resume too; spurious mid-startup smoke flakes get masked.
        "last_started_at": now_iso,
        "pre_deploy_snapshot": snapshot or "",
        "history": history,
    }

    write_state(state_path, new_state)


def take_pre_deploy_snapshot(
    project_name: str, paths: BoxPaths, manifest: dict, no_snapshot: bool,
) -> str | None:
    """Back up project data before a new release starts. Returns its name.

    `manifest` is the manifest of the release whose data is being saved.
    """
    snapshot_enabled = manifest.get("deploy", {}).get("snapshot_before_deploy", True)
    backup_type = manifest.get("backup", {}).get("type", "none")
    if not snapshot_enabled or no_snapshot or backup_type == "none":
        return None
    print("  Taking pre-deploy snapshot...")
    from boxmunge.backup import BackupKind
    from boxmunge.commands.backup_cmd import list_snapshots, run_backup
    if run_backup(project_name, paths, _lock_held=True,
                  kind=BackupKind.PREDEPLOY, manifest=manifest) != 0:
        print("  WARN: Pre-deploy backup failed — continuing deploy. "
              "A rollback of this deploy will not be able to restore data.")
        return None
    snaps = list_snapshots(paths, project_name)
    return snaps[0].name if snaps else None


def snapshot_live_release(
    project_name: str, paths: BoxPaths, no_snapshot: bool,
) -> str | None:
    """Pre-deploy snapshot of the release that is about to be replaced.

    Uses the live manifest: the outgoing release backs up its own data.
    """
    try:
        live_manifest = load_manifest(paths.project_manifest(project_name))
    except ManifestError as e:
        print(f"  WARN: Cannot read the live manifest ({e}); no pre-deploy "
              f"snapshot. A rollback of this deploy will not be able to "
              f"restore data.")
        return None
    return take_pre_deploy_snapshot(project_name, paths, live_manifest, no_snapshot)


def update_repo(repo_dir: Path, deploy_ref: str, manifest: dict) -> str | None:
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


def post_deploy_diagnostics(
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


def smoke_ok(
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
