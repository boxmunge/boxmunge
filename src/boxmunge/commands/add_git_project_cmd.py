"""boxmunge add-git-project — create a project from a git repo."""
from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from boxmunge.fs_nofollow import chown_tree_deploy, mkdir_p_deploy
from boxmunge.git_slot import GitRefError, clone
from boxmunge.identity import check_project_identity, register_project_identity
from boxmunge.log import log_operation
from boxmunge.manifest import load_manifest_as_written, validate_manifest, ManifestError
from boxmunge.project_registry import check_new_name

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def run_add_git_project(
    name: str, repo_url: str, paths: BoxPaths, ref: str | None = None,
) -> int:
    """Create a new project from a git repository. Returns 0 on success."""
    project_dir = paths.project_dir(name)

    if project_dir.exists() and (project_dir / "manifest.yml").exists():
        print(f"ERROR: Project '{name}' already exists.", file=sys.stderr)
        return 1
    try:
        check_new_name(name, paths)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    repo_dir = project_dir / "repo"
    print(f"Cloning {repo_url}...")
    try:
        clone(repo_url, repo_dir, ref or None)
    except GitRefError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    manifest_path = repo_dir / "manifest.yml"
    if not manifest_path.exists():
        print(f"ERROR: Repository has no manifest.yml at root.", file=sys.stderr)
        return 1

    try:
        manifest = load_manifest_as_written(manifest_path)
    except ManifestError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    errors, warnings = validate_manifest(manifest, name)
    if errors:
        print(f"ERROR: Manifest validation failed:", file=sys.stderr)
        for e in errors:
            print(f"  {e}")
        return 1
    for w in warnings:
        print(f"  WARN: {w}")

    manifest_id = manifest.get("id", "")
    try:
        check_project_identity(name, manifest_id, paths)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    # The project tree is deploy's whoever adds it (an operator's sudo):
    # clone made repo/ as deploy, and the rest is handed over here.
    mkdir_p_deploy(project_dir / "backups")
    mkdir_p_deploy(project_dir / "data")

    # Symlink compose.yml and manifest.yml from repo to project root
    compose_src = repo_dir / "compose.yml"
    compose_dst = project_dir / "compose.yml"
    if compose_src.exists() and not compose_dst.exists():
        compose_dst.symlink_to(compose_src)
        chown_tree_deploy(compose_dst)  # the link itself, never its target

    manifest_dst = project_dir / "manifest.yml"
    if not manifest_dst.exists():
        manifest_dst.symlink_to(manifest_path)
        chown_tree_deploy(manifest_dst)

    register_project_identity(name, manifest_id, paths)

    log_operation("add-git-project", f"Added git project from {repo_url}", paths, project=name)
    print(f"Project '{name}' created from {repo_url}.")
    print(f"  Run 'stage {name}' or 'deploy {name}' to start it.")
    return 0


def cmd_add_git_project(args: list[str]) -> None:
    """CLI entry point for add-git-project command."""
    from boxmunge.commands.argv import parse_args
    from boxmunge.paths import BoxPaths

    parsed = parse_args(
        "add-git-project", args, options={"--ref"},
        min_positional=2, max_positional=2,
    )
    name, repo_url = parsed.positional
    paths = BoxPaths()
    sys.exit(run_add_git_project(name, repo_url, paths, ref=parsed.get("--ref")))
