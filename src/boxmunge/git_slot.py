# SPDX-License-Identifier: Apache-2.0
"""Git for git-sourced projects: fetching, ref resolution, HEAD, detached
checkouts, manifest reads, and the staged clone (materialise).

An operator's ref is resolved once, to a full SHA, from origin's refs after
a fetch: 40 hex characters name that commit; otherwise exactly one of
refs/remotes/origin/<ref> and refs/tags/<ref> must exist. A plain
`git rev-parse <ref>` would pick up a stale local branch, so it is never
used for an operator's ref; refs boxmunge recorded itself (deploy history)
go through resolve_recorded_ref.

Every name is checked in Python before git runs, and every call that takes
one passes --end-of-options, so no ref is ever read as an option, a range
or a path. Run as root, git runs as the deploy user, who owns the
repository; the repository's hooks and fsmonitor never run.
"""
from __future__ import annotations

import os
import pwd
import re
import stat
import subprocess
from pathlib import Path
from collections.abc import Collection
from typing import Any

from boxmunge.fs_nofollow import (
    chmod_nofollow, chown_tree_deploy, copy_entry_nofollow, running_as_root,
)

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
        return subprocess.run(["git", "-c", "core.hooksPath=/dev/null",
                               "-c", "core.fsmonitor=false", *args], cwd=cwd,
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


def fetch(repo: Path) -> None:
    """Add origin's objects and refs; never changes HEAD or the work tree."""
    result = _git(["fetch", "-q", "--prune", "--tags", "--no-recurse-submodules", "origin"],
                  repo, timeout=GIT_TIMEOUT)
    if result.returncode != 0:
        hint = (f" (files in {repo}/.git are not the deploy user's, who runs git: "
                f"chown -R deploy:deploy {repo}, then retry)"
                if "Permission denied" in result.stderr else "")
        raise GitRefError(f"git fetch in {repo} failed: {result.stderr.strip()}{hint}")


def resolve_ref(repo: Path, ref: str) -> str:
    """An operator's ref (--ref, or the manifest's) as a full SHA, from
    origin's refs as the last fetch left them (module docstring)."""
    if not isinstance(ref, str):
        raise GitRefError(f"ref {ref!r} is not a string: quote it in manifest.yml")
    if _FULL_SHA.fullmatch(ref):
        sha = _commit(repo, ref)
        if sha != ref:
            raise GitRefError(f"commit {ref} is not in the repository (after fetching origin)")
        return sha
    _check_name(ref)
    if ref == "HEAD" or ref.startswith("refs/"):
        raise GitRefError(f"{ref!r} is not a branch or tag name: give a branch or tag of "
                          f"origin, or a full 40-character commit SHA")
    branch = _commit(repo, f"refs/remotes/origin/{ref}")
    tag = _commit(repo, f"refs/tags/{ref}")
    if branch and tag:
        raise GitRefError(f"{ref!r} is both a branch and a tag of origin; give the full "
                          f"40-character commit SHA instead")
    if branch or tag:
        return branch or tag  # type: ignore[return-value]
    hint = (" (an abbreviated commit SHA is not accepted: give all 40 characters)"
            if _SHORT_SHA.fullmatch(ref) else "")
    raise GitRefError(f"{ref!r} is neither a branch nor a tag of origin{hint}")


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
    result = _git(["checkout", "-q", "--detach", "--no-recurse-submodules",
                   "--end-of-options", sha], repo,
                  timeout=GIT_TIMEOUT)
    if result.returncode != 0:
        raise GitRefError(
            f"git checkout {sha} in {repo} failed: {result.stderr.strip()}. If an earlier "
            f"checkout was interrupted, remove {repo}/.git/index.lock if it is there and "
            f"run 'git -C {repo} checkout -f --detach {sha}' as the deploy user, then retry")


def is_full_sha(ref: str) -> bool:
    """A git install's ref: deploys and stages record full commit SHAs."""
    return bool(_FULL_SHA.fullmatch(ref or ""))


def show_manifest(repo: Path, sha: str) -> str:
    """manifest.yml as committed at `sha` (not the work tree's)."""
    _require_full_sha(sha, "read manifest.yml at")
    result = _git(["cat-file", "blob", "--end-of-options", f"{sha}:manifest.yml"], repo)
    if result.returncode != 0:
        raise GitRefError(f"cannot read manifest.yml at {sha}: {result.stderr.strip()}")
    return result.stdout


def manifest_at(repo: Path, sha: str) -> dict[str, Any]:
    """manifest.yml as committed at ``sha``, loaded in memory at the current
    schema. Raises ManifestError, naming it, when it cannot be read."""
    import yaml

    from boxmunge.manifest import ManifestError, at_current_schema
    where = Path(f"{repo}@{sha}:manifest.yml")
    try:
        doc = yaml.safe_load(show_manifest(repo, sha))
    except GitRefError as e:
        raise ManifestError(f"Cannot read manifest {where}: {e}") from e
    except yaml.YAMLError as e:
        raise ManifestError(f"Manifest is not valid YAML: {where}: {e}") from e
    if not isinstance(doc, dict):
        raise ManifestError(f"Manifest is not a YAML mapping: {where}")
    return at_current_schema(doc, where)


SUBMODULE_WARN = ("submodules are not checked out; neither production nor staging "
                  "will have them")


def materialise(project_dir: Path, sha: str, release: Path, *,
                made: Collection[str] = ()) -> list[str]:
    """Check ``sha`` out in ``release/repo``, a local clone of production's
    repository, and copy production's other release-code entries beside it
    (spec 'Git-sourced projects', steps 3-4). ``release`` is an empty
    directory. Returns the warnings to print. Production's HEAD, work tree
    and refs are never changed.

    The clone hardlinks production's objects and keeps no alternates, so it
    is independent of production's repository. It gets no hooks
    (--template=) and none of production's config, so nothing in that
    deploy-writable .git (hooks, fsmonitor, filter drivers) runs; a commit
    that would need a filter driver is refused, as are links that leave
    the staged release: staging runs only from the staged tree. ``made``
    is what the current slot records that staging created (staging_copies).
    """
    _require_full_sha(sha, "stage")
    _refuse_foreign_copies(project_dir, made)
    source, clone = project_dir / "repo", release / "repo"
    # As root, git runs as deploy: only the clone's own directory is deploy's
    # while root copies into release/, so deploy cannot plant names there.
    chmod_nofollow(release, 0o755)  # whatever root's umask: deploy must reach repo/
    clone.mkdir()
    chmod_nofollow(clone, 0o755)
    chown_tree_deploy(clone)
    result = _git(["clone", "-q", "--local", "--no-checkout", "--template=", "--",
                   str(source), str(clone)], source, timeout=GIT_TIMEOUT)
    if result.returncode != 0:
        raise GitRefError(f"cloning {source} into {clone} failed: {result.stderr.strip()}")
    _refuse_filters(clone, sha)
    checkout_detached(clone, sha)
    copy_project_entries(project_dir, release)
    _refuse_escaping_links(release)
    chown_tree_deploy(release)  # the slot is deploy's, as the user's own stage makes it
    return [SUBMODULE_WARN] if os.path.lexists(clone / ".gitmodules") else []


def _assigns_filter(attributes: str) -> bool:
    """Whether a .gitattributes text sets `filter=` on a pattern or in a
    macro (`[attr]lfs filter=lfs ...`); comments and unsets do not."""
    for line in attributes.splitlines():
        fields = line.split()
        if fields and not fields[0].startswith("#") \
                and any(f.startswith("filter=") for f in fields[1:]):
            return True
    return False


def _refuse_filters(clone: Path, sha: str) -> None:
    listing = _git(["ls-tree", "-r", "-z", "--name-only", "--end-of-options", sha], clone)
    if listing.returncode != 0:
        raise GitRefError(f"cannot list the files of {sha}: {listing.stderr.strip()}")
    for name in listing.stdout.split("\0"):
        if name != ".gitattributes" and not name.endswith("/.gitattributes"):
            continue
        blob = _git(["cat-file", "blob", "--end-of-options", f"{sha}:{name}"], clone)
        if blob.returncode != 0:
            raise GitRefError(f"cannot read {name} at {sha}: {blob.stderr.strip()}")
        if _assigns_filter(blob.stdout):
            raise GitRefError(
                f"{name} assigns a git filter (Git LFS, say) at {sha}. boxmunge's own "
                f"checkouts of a commit (the staged release, and the isolation check of a "
                f"deploy while a release is staged) run no filter drivers, so they would "
                f"not have the files production's checkout has. Use a commit without "
                f"filter attributes, or unstage and deploy it with prod-deploy")


def _refuse_foreign_copies(project_dir: Path, made: Collection[str]) -> None:
    """A top-level ``-staging`` entry that is not box state or staging's
    copy (staging_copies) would be copied into the staged release as code:
    refused, as a bundle's is (bundle.check_bundle_contents)."""
    from boxmunge.bundle import STAGING_SUFFIX, STAGING_SUFFIX_REASON
    from boxmunge.staging_copies import is_staging_copy, production_view
    dirs = production_view(project_dir)
    state = dirs.box_state()
    foreign = sorted(n for n in os.listdir(project_dir) if n.endswith(STAGING_SUFFIX)
                     and n not in state and not is_staging_copy(n, dirs, made))
    if foreign:
        raise GitRefError(f"{project_dir}: {', '.join(foreign)}: {STAGING_SUFFIX_REASON} "
                          f"(a git stage copies the project directory's release files "
                          f"into the staged release)")


def copy_project_entries(project_dir: Path, release: Path) -> None:
    """Production's release-code entries other than repo/ (.env, project.env,
    boxmunge-scripts/, operator-placed files) are copied verbatim, links as
    links and never through one (fs_nofollow.copy_entry_nofollow); a link
    into repo/ (production's are absolute) is recreated as a relative link
    to the slot's repo/. Box state and staging's ``-staging`` copies stay in
    the project dir (materialise refused any other ``-staging`` entry). The
    current slot is not read (a re-stage replaces it)."""
    from boxmunge.bundle import STAGING_SUFFIX
    from boxmunge.release import project_data_dirs
    state = project_data_dirs(project_dir, with_staged=False).box_state()
    repo = os.path.normpath(project_dir / "repo")
    src = os.open(project_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        dest = os.open(release, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            for name in sorted(os.listdir(src)):
                if name in state or name.endswith(STAGING_SUFFIX):
                    continue  # box state, or staging's copy of it (checked above)
                if stat.S_ISLNK(os.stat(name, dir_fd=src, follow_symlinks=False).st_mode):
                    target = os.path.normpath(os.path.join(project_dir,
                                                           os.readlink(name, dir_fd=src)))
                    if target == repo or target.startswith(repo + os.sep):
                        os.symlink(os.path.relpath(target, project_dir), name, dir_fd=dest)
                        continue
                copy_entry_nofollow(src, name, dest)
        finally:
            os.close(dest)
    finally:
        os.close(src)


def _refuse_escaping_links(release: Path) -> None:
    root = os.path.realpath(release)
    for dirpath, dirnames, filenames in os.walk(release):
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            if not os.path.islink(path):
                continue
            real = os.path.realpath(path)
            if real != root and not real.startswith(root + os.sep):
                raise GitRefError(
                    f"{os.path.relpath(path, release)} is a link that resolves outside the "
                    f"staged release (to {real}); staging runs only from the staged tree. "
                    f"Make it a relative link that stays inside the repository or the "
                    f"project's release files")
