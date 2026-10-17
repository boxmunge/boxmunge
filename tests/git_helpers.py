"""Real local git repositories for git-source tests (no network)."""
from __future__ import annotations

import subprocess
from pathlib import Path

_ID = ["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "init.defaultBranch=main"]


def git(*args: str, cwd: Path) -> str:
    return subprocess.run(["git", *_ID, *args], cwd=cwd, check=True, capture_output=True,
                          text=True).stdout.strip()


def origin_with(tmp: Path, files: dict[str, str]) -> tuple[Path, Path]:
    """A bare origin and a work clone with one commit of `files` on main."""
    origin, work = tmp / "origin.git", tmp / "work"
    git("init", "-q", "--bare", str(origin), cwd=tmp)
    git("clone", "-q", str(origin), str(work), cwd=tmp)
    commit(work, files, "A")
    return origin, work


def commit(work: Path, files: dict[str, str], message: str) -> str:
    for rel, text in files.items():
        (work / rel).parent.mkdir(parents=True, exist_ok=True)
        (work / rel).write_text(text)
    git("add", "-A", cwd=work)
    git("commit", "-q", "-m", message, cwd=work)
    git("push", "-q", "origin", "HEAD:main", cwd=work)
    return git("rev-parse", "HEAD", cwd=work)
