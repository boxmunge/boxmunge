"""boxmunge add-git-project — create a project from a git repo."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from boxmunge.identity import check_project_identity, register_project_identity
from boxmunge.log import log_operation
from boxmunge.manifest import load_manifest, validate_manifest, ManifestError

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def run_add_git_project(
    name: str, repo_url: str, paths: BoxPaths, ref: str | None = None,
) -> int:
    """Create a new project from a git repository. Returns 0 on success."""
    project_dir = paths.project_dir(name)

    if project_dir.exists() and (project_dir / "manifest.yml").exists():
        print(f"ERROR: Project '{name}' already exists.")
        return 1

    repo_dir = project_dir / "repo"
    print(f"Cloning {repo_url}...")
    try:
        clone_cmd = ["git", "clone"]
        if ref:
            clone_cmd.extend(["--branch", ref])
        clone_cmd.extend([repo_url, str(repo_dir)])
        subprocess.run(clone_cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"ERROR: Git clone failed: {e.stderr}")
        return 1

    manifest_path = repo_dir / "manifest.yml"
    if not manifest_path.exists():
        print(f"ERROR: Repository has no manifest.yml at root.")
        return 1

    try:
        manifest = load_manifest(manifest_path)
    except ManifestError as e:
        print(f"ERROR: {e}")
        return 1

    errors, warnings = validate_manifest(manifest, name)
    if errors:
        print(f"ERROR: Manifest validation failed:")
        for e in errors:
            print(f"  {e}")
        return 1
    for w in warnings:
        print(f"  WARN: {w}")

    manifest_id = manifest.get("id", "")
    try:
        check_project_identity(name, manifest_id, paths)
    except ValueError as e:
        print(f"ERROR: {e}")
        return 1

    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "backups").mkdir(exist_ok=True)
    (project_dir / "data").mkdir(exist_ok=True)

    # Symlink compose.yml and manifest.yml from repo to project root
    compose_src = repo_dir / "compose.yml"
    compose_dst = project_dir / "compose.yml"
    if compose_src.exists() and not compose_dst.exists():
        compose_dst.symlink_to(compose_src)

    manifest_dst = project_dir / "manifest.yml"
    if not manifest_dst.exists():
        manifest_dst.symlink_to(manifest_path)

    register_project_identity(name, manifest_id, paths)

    log_operation("add-project", f"Added git project from {repo_url}", paths, project=name)
    print(f"Project '{name}' created from {repo_url}.")
    print(f"  Run 'stage {name}' or 'deploy {name}' to start it.")
    return 0


def cmd_add_git_project(args: list[str]) -> None:
    """CLI entry point for add-git-project command."""
    from boxmunge.paths import BoxPaths

    ref = None
    positional = []
    i = 0
    while i < len(args):
        if args[i] == "--ref" and i + 1 < len(args):
            ref = args[i + 1]
            i += 2
        elif not args[i].startswith("--"):
            positional.append(args[i])
            i += 1
        else:
            i += 1

    if len(positional) < 2:
        print("Usage: boxmunge add-git-project <name> <repo-url> [--ref REF]",
              file=sys.stderr)
        sys.exit(2)

    name, repo_url = positional[0], positional[1]
    paths = BoxPaths()
    sys.exit(run_add_git_project(name, repo_url, paths, ref=ref))
