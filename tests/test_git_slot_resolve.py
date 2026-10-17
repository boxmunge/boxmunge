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
    fetch,
    head_sha,
    resolve_recorded_ref,
    resolve_ref,
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
    with patch.object(git_slot, "run_as_deploy", side_effect=hung), \
            pytest.raises(GitRefError, match="timed out"):
        checkout_detached(tmp_path, "a" * 40)


def test_a_manifest_that_is_not_utf8_is_a_git_ref_error(repos) -> None:
    _origin, work, _prod = repos
    (work / "manifest.yml").write_bytes(b"project: \xff\xfe\n")
    sha = commit(work, {}, "binary manifest")
    with pytest.raises(GitRefError, match="UTF-8"):
        show_manifest(work, sha)


def test_run_as_root_git_runs_as_the_deploy_user(repos, monkeypatch) -> None:
    """The repository is deploy's: its config (filters, fsmonitor) must never
    run as root, and git refuses a repository another user owns."""
    import pwd

    from boxmunge import as_deploy
    *_, prod = repos
    seen, argvs = {}, []
    real = subprocess.Popen

    def popen(argv, **kw):
        argvs.append(argv)
        seen.update(kw)
        return real(argv, **{k: v for k, v in kw.items()
                             if k not in ("user", "group", "extra_groups")})
    for module in (git_slot, as_deploy):
        monkeypatch.setattr(module, "running_as_root", lambda: True)
    owner = prod.stat().st_uid  # deploy owns the repository
    monkeypatch.setattr(git_slot.pwd, "getpwnam", lambda name: pwd.struct_passwd(
        (name, "x", owner, 5678, "", "/home/deploy", "/bin/sh")))
    monkeypatch.setenv("SUDO_USER", "operator")
    monkeypatch.setattr(as_deploy.subprocess, "Popen", popen)
    assert head_sha(prod)
    # Deploy's uid and gid, none of its groups (a hook gets docker; git does not).
    assert (seen["user"], seen["group"], seen["extra_groups"]) == (owner, 5678, [])
    # Nothing of root's session reaches a process deploy controls.
    assert seen["stdin"] is subprocess.DEVNULL and seen["start_new_session"] is True
    # The deploy shell's environment: deploy's config (HOME) and the system's.
    assert seen["env"]["HOME"] == "/home/deploy" and seen["env"]["USER"] == "deploy"
    assert "SUDO_USER" not in seen["env"]
    assert argvs[0][1:3] == ["-c", "core.hooksPath=/dev/null"]


def test_run_as_root_without_a_deploy_user_git_is_refused(repos, monkeypatch) -> None:
    *_, prod = repos

    def missing(name):
        raise KeyError(name)
    monkeypatch.setattr(git_slot, "running_as_root", lambda: True)
    monkeypatch.setattr(git_slot.pwd, "getpwnam", missing)
    with pytest.raises(GitRefError, match="deploy user"):
        head_sha(prod)


@pytest.mark.parametrize("where", ["repo", ".git"])
def test_run_as_root_a_repository_deploy_does_not_own_is_refused(repos, monkeypatch,
                                                                  where) -> None:
    """A repo/ an operator cloned with sudo is root's: git as deploy would fail
    with advice to add safe.directory, which is wrong here. Say to chown it."""
    import pwd
    *_, prod = repos
    other = prod.stat().st_uid + 1
    monkeypatch.setattr(git_slot, "running_as_root", lambda: True)
    monkeypatch.setattr(git_slot.pwd, "getpwnam", lambda name: pwd.struct_passwd(
        (name, "x", other, 5678, "", "/home/deploy", "/bin/sh")))
    if where == ".git":  # only the .git directory is someone else's
        real_lstat = git_slot.os.lstat

        def lstat(path, *a, **kw):
            st = real_lstat(path, *a, **kw)
            return _owned_by(st, other) if Path(path) == prod else st
        monkeypatch.setattr(git_slot.os, "lstat", lstat)
    run = patch.object(git_slot.subprocess, "run")
    with run as spawned, pytest.raises(GitRefError) as excinfo:
        head_sha(prod)
    spawned.assert_not_called()
    assert (f"{prod} must be owned by the deploy user (chown -R deploy:deploy {prod}), "
            f"then retry") in str(excinfo.value)
    assert "safe.directory" not in str(excinfo.value)


def _owned_by(st, uid):
    import os
    fields = list(st)
    fields[4] = uid
    return os.stat_result(fields)


# Operator refs (plan Task 27): resolved once, to a full SHA, from origin's refs.

def test_fetch_then_a_branch_resolves_to_the_remote_tip_not_the_stale_local_one(repos) -> None:
    _origin, work, prod = repos
    stale = git("rev-parse", "HEAD", cwd=prod)
    moved = commit(work, {"f": "b"}, "B")
    fetch(prod)
    assert git("rev-parse", "HEAD", cwd=prod) == stale       # fetch never moves HEAD
    assert resolve_ref(prod, "main") == moved != stale


def test_tags_and_full_shas_resolve(repos) -> None:
    _origin, work, prod = repos
    sha = git("rev-parse", "HEAD", cwd=work)
    git("tag", "v1", cwd=work)
    git("push", "-q", "origin", "v1", cwd=work)
    fetch(prod)
    assert resolve_ref(prod, "v1") == sha and resolve_ref(prod, sha) == sha


def test_a_local_only_branch_is_not_origins(repos) -> None:
    *_, prod = repos
    git("branch", "mine", cwd=prod)
    with pytest.raises(GitRefError, match="neither a branch nor a tag of origin"):
        resolve_ref(prod, "mine")


def test_branch_and_tag_of_one_name_is_refused(repos) -> None:
    _origin, work, prod = repos
    git("branch", "dual", cwd=work)
    git("tag", "dual", cwd=work)
    git("push", "-q", "origin", "refs/heads/dual:refs/heads/dual",
        "refs/tags/dual:refs/tags/dual", cwd=work)
    fetch(prod)
    with pytest.raises(GitRefError, match="both a branch and a tag"):
        resolve_ref(prod, "dual")


def test_abbreviated_sha_is_refused(repos) -> None:
    _origin, work, prod = repos
    sha = git("rev-parse", "HEAD", cwd=work)
    with pytest.raises(GitRefError, match="40 characters"):
        resolve_ref(prod, sha[:8])


def test_unknown_full_sha_is_refused(repos) -> None:
    with pytest.raises(GitRefError, match="not in the repository"):
        resolve_ref(repos[2], "0" * 40)


def test_a_failed_fetch_is_an_error(tmp_path) -> None:
    git("init", "-q", str(tmp_path / "lonely"), cwd=tmp_path)
    with pytest.raises(GitRefError, match="git fetch"):
        fetch(tmp_path / "lonely")


@pytest.mark.parametrize("ref", [*HOSTILE, "HEAD", "refs/heads/main"])
def test_hostile_operator_refs_refused_before_git_runs(tmp_path, ref) -> None:
    """Review Focus 3, and no name that is not a plain branch or tag name."""
    with patch.object(git_slot, "_git") as run, pytest.raises(GitRefError):
        resolve_ref(tmp_path, ref)
    run.assert_not_called()


@pytest.mark.parametrize("stderr,hint,not_hint", [
    ("error: cannot open '.git/FETCH_HEAD': Permission denied", "chown -R", "SSH key"),
    ("fatal: Unable to create '/r/.git/shallow.lock': Permission denied", "chown -R", "SSH key"),
    ("git@example.com: Permission denied (publickey).\r\nfatal: Could not read from remote "
     "repository.", "SSH key", "chown"),
    ("Host key verification failed.\nfatal: Could not read from remote repository.",
     "host key", "chown"),
    ("fatal: unable to access 'https://example.com/r.git/': Could not resolve host", "", ""),
])
def test_a_failed_fetch_hints_only_at_its_own_cause(tmp_path, stderr, hint, not_hint) -> None:
    done = subprocess.CompletedProcess(["git"], 128, "", stderr)
    with patch.object(git_slot, "_git", return_value=done), \
            pytest.raises(GitRefError) as excinfo:
        fetch(tmp_path)
    message = str(excinfo.value)
    assert message.startswith(f"git fetch in {tmp_path} failed: ")
    if hint:
        assert hint in message and not_hint not in message
    else:
        assert "chown" not in message and "SSH key" not in message


def test_the_fetch_hint_names_deploy_when_root_runs_boxmunge(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(git_slot, "running_as_root", lambda: True)
    done = subprocess.CompletedProcess(["git"], 1, "", "error: cannot open "
                                       "'.git/FETCH_HEAD': Permission denied")
    with patch.object(git_slot, "_git", return_value=done), \
            pytest.raises(GitRefError, match=f"chown -R deploy:deploy {tmp_path}"):
        fetch(tmp_path)
