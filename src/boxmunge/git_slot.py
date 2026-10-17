# SPDX-License-Identifier: Apache-2.0
"""Git for git-sourced projects: commits boxmunge recorded, HEAD, detached
checkouts and manifest reads.

The legacy-stage evidence and discard read production's repository with
these. PR C (git staging on the slot) extends this module with fetching,
operator-ref resolution and the staged clone.

Every name is checked in Python before git runs, and every call that takes
one passes --end-of-options, so no ref is ever read as an option, a range
or a path.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

GIT_TIMEOUT = 300
_FULL_SHA = re.compile(r"[0-9a-f]{40}")
_SHORT_SHA = re.compile(r"[0-9a-f]{4,39}")
# git check-ref-format's rules, plus no leading "-" (an option) or "/".
_BAD_NAME = re.compile(r"[\x00-\x20\x7f~^:?*\[\\]|\.\.|@\{|//|^[-/.]|/\.|\.lock(/|$)|[/.]$")


class GitRefError(ValueError):
    """A ref that cannot be resolved to exactly one commit, or a git failure."""


def _git(args: list[str], cwd: Path, *, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True,
                          timeout=timeout, check=False)


def _check_name(name: str) -> None:
    if not name or name == "@" or _BAD_NAME.search(name):
        raise GitRefError(f"{name!r} is not a valid git ref name or SHA")


def _commit(repo: Path, name: str) -> str | None:
    _check_name(name)
    result = _git(["rev-parse", "-q", "--verify", "--end-of-options", f"{name}^{{commit}}"], repo)
    return result.stdout.strip() if result.returncode == 0 else None


def rev_parse(repo: Path, name: str) -> str | None:
    """The full SHA of the commit `name` names, or None if it names none.
    Raises GitRefError for a name that is not a valid ref or SHA."""
    return _commit(repo, name)


def resolve_recorded_ref(repo: Path, ref: str) -> str:
    """A ref boxmunge recorded itself (deploy history): a full SHA, or a
    short one written by 0.10.1 that git resolves to exactly one commit."""
    if not _SHORT_SHA.fullmatch(ref or "") and not _FULL_SHA.fullmatch(ref or ""):
        raise GitRefError(f"recorded ref {ref!r} is not a commit SHA")
    sha = _commit(repo, ref)
    if sha is None:
        raise GitRefError(f"recorded commit {ref} is not in the repository, or is ambiguous")
    if not sha.startswith(ref):
        # rev-parse prefers a ref of that name to the abbreviated SHA.
        raise GitRefError(f"recorded commit {ref} is shadowed by a branch or tag of that "
                          f"name (it names {sha}); remove the branch or tag and retry")
    return sha


def head_sha(repo: Path) -> str:
    sha = _commit(repo, "HEAD")
    if sha is None:
        raise GitRefError(f"{repo} has no HEAD commit")
    return sha


def _require_full_sha(sha: str, what: str) -> None:
    if not _FULL_SHA.fullmatch(sha or ""):
        raise GitRefError(f"refusing to {what} {sha!r}: not a full SHA")


def checkout_detached(repo: Path, sha: str) -> None:
    """Check out `sha` with HEAD detached; the repository's hooks never run."""
    _require_full_sha(sha, "check out")
    result = _git(["-c", "core.hooksPath=/dev/null", "checkout", "-q", "--detach",
                   "--end-of-options", sha], repo, timeout=GIT_TIMEOUT)
    if result.returncode != 0:
        raise GitRefError(f"git checkout {sha} in {repo} failed: {result.stderr.strip()}")


def show_manifest(repo: Path, sha: str) -> str:
    """manifest.yml as committed at `sha` (not the work tree's)."""
    _require_full_sha(sha, "read manifest.yml at")
    result = _git(["cat-file", "blob", "--end-of-options", f"{sha}:manifest.yml"], repo)
    if result.returncode != 0:
        raise GitRefError(f"cannot read manifest.yml at {sha}: {result.stderr.strip()}")
    return result.stdout
