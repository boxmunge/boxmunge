"""Shared bundle extraction and file-copy helpers."""
from __future__ import annotations

import shutil
import tarfile
from pathlib import Path


def extract_bundle(bundle_path: Path, dest: Path) -> Path:
    """Extract a tar.gz bundle and return the project directory inside.

    Raises ValueError if the archive doesn't contain exactly one top-level dir.
    """
    if not bundle_path.exists():
        raise ValueError(f"Bundle not found: {bundle_path}")

    if not tarfile.is_tarfile(bundle_path):
        raise ValueError(f"Not a valid tar.gz file: {bundle_path}")

    with tarfile.open(bundle_path, "r:gz") as tar:
        # Security: reject paths that escape the extraction dir
        for member in tar.getmembers():
            if member.name.startswith("/") or ".." in member.name:
                raise ValueError(
                    f"Unsafe path in archive: {member.name}"
                )
        tar.extractall(path=dest, filter="data")

    # Find the single top-level directory
    top_entries = [
        e for e in dest.iterdir()
        if e.is_dir() and not e.name.startswith(".")
    ]
    if len(top_entries) != 1:
        names = [e.name for e in top_entries]
        raise ValueError(
            f"Bundle must contain exactly one top-level directory, "
            f"found: {names}"
        )

    return top_entries[0]


def copy_project_files(src: Path, dest: Path, is_upgrade: bool) -> None:
    """Copy project files from extracted bundle to project directory.

    On upgrade, preserves project.env (secrets).
    """
    existing_env = None
    if is_upgrade:
        env_path = dest / "project.env"
        if env_path.exists():
            existing_env = env_path.read_text()

    # Copy everything from bundle into project dir
    for item in src.iterdir():
        dest_item = dest / item.name
        if item.is_dir():
            if dest_item.exists():
                shutil.rmtree(dest_item)
            shutil.copytree(item, dest_item)
        else:
            shutil.copy2(item, dest_item)

    # Restore preserved env file on upgrade
    if is_upgrade and existing_env is not None:
        from boxmunge.fileutil import atomic_write_text
        atomic_write_text(dest / "project.env", existing_env, mode=0o600)

    # Ensure required subdirectories exist
    (dest / "backups").mkdir(exist_ok=True)
    (dest / "data").mkdir(exist_ok=True)

    # Make scripts executable
    for sh_file in dest.rglob("*.sh"):
        sh_file.chmod(sh_file.stat().st_mode | 0o755)
