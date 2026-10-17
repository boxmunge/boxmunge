"""A deployed git-sourced project over a local origin (no network, no Docker)."""
from __future__ import annotations

import os
from pathlib import Path

from boxmunge.commands.deploy import run_deploy
from boxmunge.project_registry import add_project
from tests.bundle_helpers import SAFE_COMPOSE, manifest_text
from tests.git_helpers import commit, git, origin_with
from tests.stage_helpers import staging_docker_off


def git_manifest(origin: Path, backup: str = "none", extra: str = "") -> str:
    return manifest_text(backup=backup).replace(
        "source: bundle\n", f"source: git\nrepo: {origin}\nref: main\n") + extra


def git_project(paths, tmp_path, backup: str = "none", compose: str = SAFE_COMPOSE,
                files: dict[str, str] | None = None) -> tuple[Path, Path]:
    """(project dir, work clone): myapp cloned from tmp_path/origin.git, its
    compose.yml and manifest.yml linked into repo/ as add-git-project does,
    and deployed once."""
    origin, work = origin_with(tmp_path, {"compose.yml": compose, "VERSION": "A\n",
                                          **(files or {})})
    commit(work, {"manifest.yml": git_manifest(origin, backup)}, "manifest")
    add_project("myapp", paths)
    pdir = paths.project_dir("myapp")
    pdir.mkdir(parents=True)
    git("clone", "-q", str(origin), str(pdir / "repo"), cwd=tmp_path)
    for name in ("compose.yml", "manifest.yml"):
        os.symlink(pdir / "repo" / name, pdir / name)
    with staging_docker_off():
        assert run_deploy("myapp", paths) == 0
    return pdir, work
