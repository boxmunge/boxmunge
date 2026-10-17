# SPDX-License-Identifier: Apache-2.0
"""Git for git-sourced projects: commits boxmunge recorded, HEAD, detached
checkouts and manifest reads.

The legacy-stage evidence and discard read production's repository with
these. PR C (git staging on the slot) extends this module with fetching,
operator-ref resolution and the staged clone.

Every name is checked in Python before git runs, and every call that takes
one passes --end-of-options, so no ref is ever read as an option, a range
or a path. Run as root (legacy-stage is operator-only), git runs as the
deploy user, who owns the repository.
"""
from __future__ import annotations

import os
import pwd
import re
import subprocess
from pathlib import Path

from boxmunge.fs_nofollow import running_as_root

GIT_TIMEOUT = 300
_FULL_SHA = re.compile(r"[0-9a-f]{40}")
_SHORT_SHA = re.compile(r"[0-9a-f]{4,39}")
# git check-ref-format's rules, plus no leading "-" (an option) or "/".
_BAD_NAME = re.compile(r"[\x00-\x20\x7f~^:?*\[\\]|\.\.|@\{|//|^[-/.]|/\.|\.lock(/|$)|[/.]$")


class GitRefError(ValueError):
    """A ref that cannot be resolved to exactly one commit, or a git failure."""


def _require_deploy_owned(repo: Path, uid: int) -> None:
    """git as deploy refuses a repository deploy does not own (one cloned with
    sudo), and its advice to add safe.directory is wrong here: say to chown."""
    for path in (repo, repo / ".git"):
        try:
            owner = os.lstat(path).st_uid
        except FileNotFoundError:
            continue  # not a repository: git says so
        except OSError as e:
            raise GitRefError(f"cannot inspect {path}: {e}") from e
        if owner != uid:
            raise GitRefError(f"{repo} must be owned by the deploy user (chown -R "
                              f"deploy:deploy {repo}), then retry; {path} is owned by "
                              f"uid {owner}")


def _as_deploy(repo: Path) -> dict:
    """subprocess arguments that run git as the deploy user when we are root.
    The repository and its config are deploy's, so whatever git runs from
    them (filters, fsmonitor) is deploy's code: it runs as deploy, with no
    stdin, in its own session (no controlling terminal to inject into) and
    a minimal environment (git refuses another user's repository anyway)."""
    if not running_as_root():
        return {}
    try:
        pw = pwd.getpwnam("deploy")
    except KeyError as e:
        raise GitRefError("running as root, git runs as the deploy user, and there is no "
                          "deploy user") from e
    _require_deploy_owned(repo, pw.pw_uid)
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": pw.pw_dir,
           "LANG": os.environ.get("LANG", "C.UTF-8"), "GIT_CONFIG_NOSYSTEM": "1"}
    return {"user": pw.pw_uid, "group": pw.pw_gid, "extra_groups": [], "env": env,
            "stdin": subprocess.DEVNULL, "start_new_session": True}


def _git(args: list[str], cwd: Path, *, timeout: int = 60) -> subprocess.CompletedProcess:
    """git's result; a hang or output that is not UTF-8 raises GitRefError,
    so callers handle one error type. The repository's hooks never run."""
    try:
        return subprocess.run(["git", "-c", "core.hooksPath=/dev/null", *args], cwd=cwd,
                              capture_output=True, text=True, timeout=timeout, check=False,
                              **_as_deploy(cwd))
    except subprocess.TimeoutExpired as e:
        raise GitRefError(f"git {args[0]} in {cwd} timed out after {timeout}s") from e
    except UnicodeDecodeError as e:
        raise GitRefError(f"git {args[0]} in {cwd} wrote output that is not UTF-8: {e}") from e


def _check_name(name: str) -> None:
    if not name or name == "@" or _BAD_NAME.search(name):
        raise GitRefError(f"{name!r} is not a valid git ref name or SHA")


def _commit(repo: Path, name: str) -> str | None:
    _check_name(name)
    result = _git(["rev-parse", "-q", "--verify", "--end-of-options", f"{name}^{{commit}}"], repo)
    if result.returncode == 0:
        return result.stdout.strip()
    # -q --verify exits 1, silently, for a name that names no single commit;
    # any other exit is git failing (not a repository, dubious ownership, corruption).
    if result.returncode == 1 and not result.stderr.strip():
        return None
    raise GitRefError(f"git rev-parse {name} in {repo} failed (exit {result.returncode}): "
                      f"{result.stderr.strip()}")


def rev_parse(repo: Path, name: str) -> str | None:
    """The full SHA of the commit `name` names, or None if it names none.
    Raises GitRefError for a name that is not a valid ref or SHA, or when
    git itself fails."""
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
    result = _git(["checkout", "-q", "--detach", "--end-of-options", sha], repo,
                  timeout=GIT_TIMEOUT)
    if result.returncode != 0:
        raise GitRefError(f"git checkout {sha} in {repo} failed: {result.stderr.strip()}")


def show_manifest(repo: Path, sha: str) -> str:
    """manifest.yml as committed at `sha` (not the work tree's)."""
    _require_full_sha(sha, "read manifest.yml at")
    result = _git(["cat-file", "blob", "--end-of-options", f"{sha}:manifest.yml"], repo)
    if result.returncode != 0:
        raise GitRefError(f"cannot read manifest.yml at {sha}: {result.stderr.strip()}")
    return result.stdout
