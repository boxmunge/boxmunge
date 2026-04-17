# SPDX-License-Identifier: Apache-2.0
"""Platform stash — capture state for safe upgrades.

Creates a dated tarball of all project files, config, secrets,
deploy state, and platform version. Used automatically during
boxmunge upgrade; not a user-facing command.
"""

import os
import tarfile
from datetime import datetime, timezone
from pathlib import Path

from boxmunge.paths import BoxPaths


def create_stash(paths: BoxPaths) -> Path:
    """Create a stash archive of the current platform state.

    Returns the path to the created archive.
    """
    paths.stashes.mkdir(parents=True, exist_ok=True)
    os.chmod(paths.stashes, 0o700)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%S")
    archive_path = paths.stashes / f"boxmunge-stash-{ts}.tar.gz"

    with tarfile.open(archive_path, "w:gz") as tar:
        for config_file in [paths.config_file, paths.host_secrets, paths.backup_key, paths.version_file]:
            if config_file.exists():
                tar.add(config_file, arcname=f"config/{config_file.name}")

        if paths.deploy_state.exists():
            for state_file in paths.deploy_state.iterdir():
                if state_file.is_file():
                    tar.add(state_file, arcname=f"state/deploy/{state_file.name}")

        if paths.projects.exists():
            for project_dir in sorted(paths.projects.iterdir()):
                if not project_dir.is_dir():
                    continue
                project_name = project_dir.name
                for filename in ["manifest.yml", "compose.yml", "project.env", "secrets.env"]:
                    filepath = project_dir / filename
                    if filepath.exists():
                        tar.add(filepath, arcname=f"projects/{project_name}/{filename}")
                scripts_dir = project_dir / "boxmunge-scripts"
                if scripts_dir.exists():
                    for script in scripts_dir.iterdir():
                        if script.is_file():
                            tar.add(script, arcname=f"projects/{project_name}/boxmunge-scripts/{script.name}")

    os.chmod(archive_path, 0o600)
    return archive_path


def list_stashes(paths: BoxPaths) -> list[Path]:
    """List stash archives, newest first."""
    if not paths.stashes.exists():
        return []
    return sorted(
        paths.stashes.glob("boxmunge-stash-*.tar.gz"),
        key=lambda f: f.name,
        reverse=True,
    )


def prune_stashes(paths: BoxPaths, keep: int = 3) -> list[Path]:
    """Remove old stashes, keeping the N most recent. Returns pruned paths."""
    stashes = list_stashes(paths)
    to_prune = stashes[keep:]
    for stash in to_prune:
        stash.unlink()
    return to_prune
