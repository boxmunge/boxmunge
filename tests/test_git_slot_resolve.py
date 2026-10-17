"""Recorded refs, HEAD, detached checkout and manifest reads, against real
local repositories (spec 'Git-sourced projects', step 2; plan Tasks 27, 32)."""
from __future__ import annotations

import subprocess
from collections import defaultdict
from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge import git_slot
from boxmunge.git_slot import (
    GitRefError,
    checkout_detached,
    head_sha,
    resolve_recorded_ref,
    rev_parse,
    show_manifest,
)
from tests.git_helpers import commit, git, origin_with

HOSTILE = ["--upload-pack=touch /tmp/x", "main..HEAD", "../x", "a b", "", "main^", "-",
           "HEAD@{1}", "x:y", "a\nb", "refs/heads/x.lock", "x/", "x//y", "@"]


@pytest.fixture
def repos(tmp_path):
    origin, work = origin_with(tmp_path, {"manifest.yml": "project: g\n", "f": "a"})
    prod = tmp_path / "prod"
    git("clone", "-q", str(origin), str(prod), cwd=tmp_path)
    return origin, work, prod


def _ambiguous_prefix(repo: Path) -> str:
    """A 4-hex prefix shared by two commits. fast-import's fixed dates make
    the commits, and so the prefix, the same on every run."""
    stream = "".join(f"commit refs/heads/many\ncommitter t <t@example.com> 1700000000 +0000\n"
                     f"data {len(f'c{i}')}\nc{i}\n" for i in range(1500))
    subprocess.run(["git", "fast-import", "--quiet"], cwd=repo, input=stream, text=True,
                   check=True)
    by_prefix: defaultdict[str, int] = defaultdict(int)
    for sha in git("rev-list", "refs/heads/many", cwd=repo).split():
        by_prefix[sha[:4]] += 1
    return next(p for p, n in sorted(by_prefix.items()) if n > 1)


def test_recorded_full_and_short_shas_resolve(repos) -> None:
    _origin, work, prod = repos
    sha = git("rev-parse", "HEAD", cwd=work)
    assert resolve_recorded_ref(prod, sha) == sha
    assert resolve_recorded_ref(prod, sha[:8]) == sha   # 0.10.1's recorded short refs
    assert resolve_recorded_ref(prod, sha[:7]) == sha


def test_ambiguous_short_sha_is_refused(repos) -> None:
    prefix = _ambiguous_prefix(repos[2])
    with pytest.raises(GitRefError, match="ambiguous"):
        resolve_recorded_ref(repos[2], prefix)


@pytest.mark.parametrize("ref", ["0" * 40, "deadbeef"])
def test_unknown_recorded_sha_is_refused(repos, ref) -> None:
    with pytest.raises(GitRefError, match="not in the repository"):
        resolve_recorded_ref(repos[2], ref)


@pytest.mark.parametrize("ref", ["main", "v1", "abc", "a" * 41, "ABCDEF12"])
def test_recorded_ref_must_be_a_sha(tmp_path, ref) -> None:
    with patch.object(git_slot, "_git") as run, pytest.raises(GitRefError, match="not a commit SHA"):
        resolve_recorded_ref(tmp_path, ref)
    run.assert_not_called()


def test_a_tag_named_like_a_short_sha_is_not_taken_for_it(repos) -> None:
    _origin, work, prod = repos
    first = git("rev-parse", "HEAD", cwd=prod)
    second = commit(work, {"f": "b"}, "B")
    git("fetch", "-q", "origin", cwd=prod)
    git("tag", second[:8], first, cwd=prod)   # the tag shadows the SHA prefix in rev-parse
    with pytest.raises(GitRefError, match="a branch or tag"):
        resolve_recorded_ref(prod, second[:8])


def test_rev_parse(repos) -> None:
    _origin, work, prod = repos
    sha = git("rev-parse", "HEAD", cwd=work)
    git("tag", "v1", cwd=prod)
    assert rev_parse(prod, "main") == sha
    assert rev_parse(prod, "v1") == sha
    assert rev_parse(prod, "refs/remotes/origin/main") == sha
    assert rev_parse(prod, sha[:8]) == sha
    assert rev_parse(prod, "no-such-branch") is None
    assert rev_parse(prod, "0" * 40) is None


def test_head_sha(repos) -> None:
    _origin, work, prod = repos
    assert head_sha(prod) == git("rev-parse", "HEAD", cwd=work)


def test_head_sha_of_an_empty_repository_is_refused(tmp_path) -> None:
    git("init", "-q", str(tmp_path / "empty"), cwd=tmp_path)
    with pytest.raises(GitRefError, match="no HEAD commit"):
        head_sha(tmp_path / "empty")


def test_checkout_detached_leaves_the_work_tree_at_the_sha(repos) -> None:
    _origin, work, prod = repos
    first = git("rev-parse", "HEAD", cwd=prod)
    commit(work, {"f": "b", "new": "n"}, "B")
    git("pull", "-q", "--ff-only", cwd=prod)
    (prod / ".git" / "hooks" / "post-checkout").write_text("#!/bin/sh\ntouch hooked\n")
    (prod / ".git" / "hooks" / "post-checkout").chmod(0o755)
    checkout_detached(prod, first)
    assert head_sha(prod) == first
    assert (prod / "f").read_text() == "a" and not (prod / "new").exists()
    assert subprocess.run(["git", "symbolic-ref", "-q", "HEAD"], cwd=prod).returncode == 1
    assert not (prod / "hooked").exists()   # hooks never run


@pytest.mark.parametrize("sha", ["abcdef12", "main", "HEAD", "--orphan=x", ""])
def test_checkout_detached_refuses_anything_but_a_full_sha(tmp_path, sha) -> None:
    with patch.object(git_slot, "_git") as run, pytest.raises(GitRefError, match="full SHA"):
        checkout_detached(tmp_path, sha)
    run.assert_not_called()


def test_checkout_detached_of_an_unknown_sha_fails_noisily(repos) -> None:
    with pytest.raises(GitRefError, match="checkout"):
        checkout_detached(repos[2], "0" * 40)


def test_show_manifest_reads_the_commit_not_the_work_tree(repos) -> None:
    _origin, work, prod = repos
    first = git("rev-parse", "HEAD", cwd=prod)
    (prod / "manifest.yml").write_text("project: edited\n")
    assert show_manifest(prod, first) == "project: g\n"


def test_show_manifest_without_a_manifest_fails(repos) -> None:
    _origin, work, _prod = repos
    git("rm", "-q", "manifest.yml", cwd=work)
    git("commit", "-q", "-m", "rm", cwd=work)
    with pytest.raises(GitRefError, match="manifest.yml"):
        show_manifest(work, git("rev-parse", "HEAD", cwd=work))


@pytest.mark.parametrize("sha", ["abcdef12", "HEAD", "main", "--output=/tmp/x"])
def test_show_manifest_refuses_anything_but_a_full_sha(tmp_path, sha) -> None:
    with patch.object(git_slot, "_git") as run, pytest.raises(GitRefError, match="full SHA"):
        show_manifest(tmp_path, sha)
    run.assert_not_called()


@pytest.mark.parametrize("ref", HOSTILE)
def test_hostile_refs_refused_before_git_runs(tmp_path, ref) -> None:
    """Review Focus 3: no ref is ever read as an option, a range or a path."""
    with patch.object(git_slot, "_git") as run:
        with pytest.raises(GitRefError):
            rev_parse(tmp_path, ref)
        with pytest.raises(GitRefError):
            resolve_recorded_ref(tmp_path, ref)
        with pytest.raises(GitRefError):
            checkout_detached(tmp_path, ref)
        with pytest.raises(GitRefError):
            show_manifest(tmp_path, ref)
    run.assert_not_called()


def test_every_ref_taking_call_ends_options(repos) -> None:
    _origin, _work, prod = repos
    sha = head_sha(prod)
    real = git_slot._git
    seen: list[list[str]] = []

    def spy(args, cwd, **kw):
        seen.append(args)
        return real(args, cwd, **kw)

    with patch.object(git_slot, "_git", side_effect=spy):
        rev_parse(prod, "main")
        resolve_recorded_ref(prod, sha[:8])
        head_sha(prod)
        show_manifest(prod, sha)
        checkout_detached(prod, sha)
    assert seen and all("--end-of-options" in args for args in seen)
    assert all(args[args.index("--end-of-options") + 1].startswith(("main", sha[:8], "HEAD", sha))
               for args in seen)


def test_a_git_failure_is_an_error_not_no_commit(tmp_path) -> None:
    """rev-parse exits 1 for a name that names no commit; anything else is git failing."""
    (tmp_path / "not-a-repo").mkdir()
    with pytest.raises(GitRefError, match="not a git repository"):
        rev_parse(tmp_path / "not-a-repo", "main")
    with pytest.raises(GitRefError, match="not a git repository"):
        head_sha(tmp_path / "not-a-repo")
    with pytest.raises(GitRefError, match="not a git repository"):
        resolve_recorded_ref(tmp_path / "not-a-repo", "abcdef12")


def test_a_git_timeout_is_a_git_ref_error(tmp_path) -> None:
    hung = subprocess.TimeoutExpired(["git"], 60)
    with patch.object(git_slot.subprocess, "run", side_effect=hung), \
            pytest.raises(GitRefError, match="timed out"):
        checkout_detached(tmp_path, "a" * 40)


def test_a_manifest_that_is_not_utf8_is_a_git_ref_error(repos) -> None:
    _origin, work, _prod = repos
    (work / "manifest.yml").write_bytes(b"project: \xff\xfe\n")
    sha = commit(work, {}, "binary manifest")
    with pytest.raises(GitRefError, match="UTF-8"):
        show_manifest(work, sha)
