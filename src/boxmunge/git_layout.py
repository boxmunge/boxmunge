# SPDX-License-Identifier: Apache-2.0
"""A git project's link layout, and what to tell the operator about it.

`add-git-project` links `<p>/manifest.yml` and `<p>/compose.yml` into the
checkout at `<p>/repo/`, so every deploy reads the repository's files.
boxmunge never writes those links (manifest.write_manifest refuses) and
never stashes them. Upgrades by earlier releases replaced the manifest link with a
regular file; such a project keeps deploying a frozen copy until the link
is put back, which only the operator can decide to do.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from boxmunge.manifest import CURRENT_SCHEMA_VERSION, ManifestError, load_manifest_as_written
from boxmunge.paths import BoxPaths
from boxmunge.project_alerts import alert_once, clear_alert

LINKED_FILES = ("manifest.yml", "compose.yml")


def links_into_repo(project_dir: Path, name: str) -> bool:
    """True if `<p>/<name>` is a symlink that resolves inside `<p>/repo/`."""
    path = project_dir / name
    if not path.is_symlink():
        return False
    return path.resolve().is_relative_to((project_dir / "repo").resolve())


def unlinked_files(project_dir: Path, manifest: dict[str, Any]) -> list[str]:
    """The LINKED_FILES of a git project that are not links into repo/.

    Only a project with a checkout counts: a bundle may declare
    `source: git` without ever having had one.
    """
    if manifest.get("source") != "git" or not (project_dir / "repo").is_dir():
        return []
    return [n for n in LINKED_FILES if not links_into_repo(project_dir, n)]


def relink_advice(project_dir: Path, unlinked: list[str]) -> str:
    """What is wrong and the exact commands that fix it."""
    p = project_dir.name
    steps = "; ".join(
        f"diff {project_dir}/{n} {project_dir}/repo/{n} && "
        f"ln -sfn repo/{n} {project_dir}/{n}" for n in unlinked)
    return (f"{p}: source is git, but {', '.join(unlinked)} "
            f"{'is' if len(unlinked) == 1 else 'are'} not a link into repo/, so "
            f"deploys read a frozen copy instead of the repository. Confirm the "
            f"repository's file is the one to use, then re-link: {steps}")


def unlinked_projects(paths: BoxPaths) -> dict[str, str]:
    """Every project with a broken git layout, mapped to relink_advice (or
    to why its manifest could not be read to tell)."""
    found: dict[str, str] = {}
    if not paths.projects.is_dir():
        return found
    for project_dir in sorted(paths.projects.iterdir()):
        manifest_path = project_dir / "manifest.yml"
        if not (manifest_path.exists() or manifest_path.is_symlink()):
            continue
        try:
            manifest = load_manifest_as_written(manifest_path)
        except ManifestError as e:
            found[project_dir.name] = f"cannot check its git layout: {e}"
            continue
        unlinked = unlinked_files(project_dir, manifest)
        if unlinked:
            found[project_dir.name] = relink_advice(project_dir, unlinked)
    return found


def alert_unlinked(paths: BoxPaths, project_dir: Path, manifest: dict[str, Any]) -> list[str]:
    """Alert once about a broken layout (clearing the record once it is
    fixed, so a recurrence alerts). Returns the unlinked files."""
    p = project_dir.name
    unlinked = unlinked_files(project_dir, manifest)
    if not unlinked:
        clear_alert(paths, p, "git-layout")
        return []
    alert_once(paths, p, "git-layout", {"files": unlinked},
               title=f"{p}: git project not linked to its repository",
               message=relink_advice(project_dir, unlinked), component="upgrade")
    return unlinked


def schema_advice(project: str, written: object) -> str:
    """What to tell the operator about a repository manifest at an old schema
    (`written` is its schema_version, None when absent)."""
    if written is None:
        return (f"{project}: the repository's manifest.yml has no schema_version "
                f"(read as schema 1). Set schema_version: {CURRENT_SCHEMA_VERSION} "
                f"in the repository and deploy.")
    return (f"{project}: the repository's manifest.yml uses schema {written}; "
            f"boxmunge migrates it in memory to schema {CURRENT_SCHEMA_VERSION}. "
            f"Update it in the repository (set schema_version: "
            f"{CURRENT_SCHEMA_VERSION}) and deploy.")


def alert_old_schema(paths: BoxPaths, project: str, written: object) -> None:
    """Alert once per (repository schema, current schema) pair."""
    alert_once(paths, project, "manifest-schema",
               {"repository_schema": written, "current_schema": CURRENT_SCHEMA_VERSION},
               title=f"{project}: update manifest.yml in the repository",
               message=schema_advice(project, written), component="upgrade")
