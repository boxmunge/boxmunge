"""The slot's clone (spec 'Git-sourced projects', steps 3-4): production's
checkout semantics, never production's HEAD, and nothing in the commit or
production's repository runs code or reaches outside the staged release."""
from __future__ import annotations

import os

import pytest

from boxmunge.git_slot import SUBMODULE_WARN, GitRefError, materialise
from tests.git_helpers import commit, git, origin_with


@pytest.fixture
def project(tmp_path):
    origin, work = origin_with(tmp_path, {"compose.yml": "services: {}\n",
                                          "manifest.yml": "project: myapp\n",
                                          ".gitattributes": "secret export-ignore\n",
                                          "secret": "s"})
    pdir = tmp_path / "projects" / "myapp"
    pdir.mkdir(parents=True)
    git("clone", "-q", str(origin), str(pdir / "repo"), cwd=tmp_path)
    for name in ("compose.yml", "manifest.yml"):
        os.symlink(pdir / "repo" / name, pdir / name)   # production uses absolute links
    (pdir / ".env").write_text("X=1\n")
    (pdir / "boxmunge-scripts").mkdir()
    (pdir / "boxmunge-scripts" / "smoke.sh").write_text("true\n")
    (pdir / "secrets.env").write_text("S=1\n")
    (pdir / "data").mkdir()
    (pdir / "data-staging").mkdir()        # staging's copy of production's data/
    return pdir, work


def _release(tmp_path):
    release = tmp_path / "slot" / "release"
    release.mkdir(parents=True)
    return release


def _push(pdir, work, files, message="B") -> str:
    sha = commit(work, files, message)
    git("fetch", "-q", "origin", cwd=pdir / "repo")
    return sha


def test_materialise_checks_out_the_sha_in_an_independent_clone(project, tmp_path) -> None:
    pdir, work = project
    head = git("rev-parse", "HEAD", cwd=pdir / "repo")
    target = _push(pdir, work, {"compose.yml": "services: {web: {image: nginx}}\n"})
    release = _release(tmp_path)
    assert materialise(pdir, target, release) == []
    assert git("rev-parse", "HEAD", cwd=release / "repo") == target
    assert git("rev-parse", "HEAD", cwd=pdir / "repo") == head          # production untouched
    assert git("status", "--porcelain", cwd=pdir / "repo") == ""
    assert not (release / "repo" / ".git" / "objects" / "info" / "alternates").exists()
    assert not (release / "repo" / ".git" / "hooks").exists()
    assert (release / "repo" / "secret").read_text() == "s"           # export-ignore present


def test_project_entries_copied_and_links_made_relative(project, tmp_path) -> None:
    pdir, _work = project
    release = _release(tmp_path)
    materialise(pdir, git("rev-parse", "HEAD", cwd=pdir / "repo"), release)
    assert os.readlink(release / "compose.yml") == "repo/compose.yml"
    assert os.readlink(release / "manifest.yml") == "repo/manifest.yml"
    assert (release / "compose.yml").read_text() == "services: {}\n"
    assert (release / ".env").read_text() == "X=1\n"
    assert (release / "boxmunge-scripts" / "smoke.sh").read_text() == "true\n"
    for state in ("secrets.env", "data", "data-staging"):                # box state stays
        assert not os.path.lexists(release / state)


def test_gitmodules_warns(project, tmp_path) -> None:
    pdir, work = project
    sha = _push(pdir, work, {".gitmodules": "[submodule \"x\"]\n"}, "S")
    assert materialise(pdir, sha, _release(tmp_path)) == [SUBMODULE_WARN]


def test_productions_hooks_and_config_never_run(project, tmp_path) -> None:
    """Production's .git is deploy-writable: its hooks, fsmonitor and filter
    drivers are not the clone's, and git runs none of them."""
    pdir, work = project
    sha = _push(pdir, work, {"VERSION": "B\n"})
    marker = tmp_path / "ran"
    script = tmp_path / "evil.sh"
    script.write_text(f"#!/bin/sh\ntouch {marker}\ncat\n")
    script.chmod(0o755)
    hook = pdir / "repo" / ".git" / "hooks" / "post-checkout"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\n")
    hook.chmod(0o755)
    git("config", "core.fsmonitor", str(script), cwd=pdir / "repo")
    git("config", "filter.evil.smudge", str(script), cwd=pdir / "repo")
    git("config", "--add", "include.path", str(tmp_path / "nowhere"), cwd=pdir / "repo")
    release = _release(tmp_path)
    materialise(pdir, sha, release)
    assert not marker.exists()
    config = (release / "repo" / ".git" / "config").read_text()
    assert "evil" not in config and "fsmonitor" not in config


def test_a_commit_that_assigns_a_filter_is_refused(project, tmp_path) -> None:
    """A filter driver (Git LFS, say) is not run in the staged checkout, so
    staging would not see the files production's checkout has: refused."""
    pdir, work = project
    sha = _push(pdir, work, {"sub/.gitattributes": "# lfs\n*.bin filter=lfs -text\n"})
    with pytest.raises(GitRefError, match=r"sub/\.gitattributes assigns a git filter"):
        materialise(pdir, sha, _release(tmp_path))


def test_filter_unset_and_comments_are_fine(project, tmp_path) -> None:
    pdir, work = project
    sha = _push(pdir, work, {".gitattributes": "# filter=lfs\n*.bin -filter !filter\n"})
    assert materialise(pdir, sha, _release(tmp_path)) == []


@pytest.mark.parametrize("target", ["/etc", "../../../outside", "../../x"])
def test_a_link_out_of_the_staged_release_is_refused(project, tmp_path, target) -> None:
    pdir, work = project
    os.symlink(target, work / "escape")
    sha = _push(pdir, work, {})
    with pytest.raises(GitRefError, match="escape is a link that resolves outside"):
        materialise(pdir, sha, _release(tmp_path))


def test_links_inside_the_staged_release_are_fine(project, tmp_path) -> None:
    pdir, work = project
    os.symlink("compose.yml", work / "alias.yml")
    os.symlink("../.env", work / "env-link")
    sha = _push(pdir, work, {})
    release = _release(tmp_path)
    materialise(pdir, sha, release)
    assert (release / "repo" / "env-link").read_text() == "X=1\n"


def test_a_production_entry_linking_out_of_the_project_is_refused(project, tmp_path) -> None:
    pdir, _work = project
    os.symlink(tmp_path / "elsewhere", pdir / "conf")
    with pytest.raises(GitRefError, match="conf is a link that resolves outside"):
        materialise(pdir, git("rev-parse", "HEAD", cwd=pdir / "repo"), _release(tmp_path))


def test_only_a_full_sha_is_materialised(project, tmp_path) -> None:
    pdir, _work = project
    with pytest.raises(GitRefError, match="full SHA"):
        materialise(pdir, git("rev-parse", "HEAD", cwd=pdir / "repo")[:12], _release(tmp_path))


def test_only_the_clone_is_deploys_while_root_copies(project, tmp_path, monkeypatch) -> None:
    """As root, git runs as deploy: the clone's empty directory is handed to
    deploy before the clone, and the rest of release/ only once root has
    copied into it and checked its links, so deploy cannot plant a name
    there for root to write through."""
    from boxmunge import git_slot
    pdir, _work = project
    calls = []
    monkeypatch.setattr(git_slot, "chown_tree_deploy", lambda path: calls.append(
        (path.name, os.path.lexists(path / ".git"), os.path.lexists(path / ".env"))))
    release = _release(tmp_path)
    materialise(pdir, git("rev-parse", "HEAD", cwd=pdir / "repo"), release)
    assert calls == [("repo", False, False), ("release", False, True)]


def test_a_copy_the_slot_made_stays_in_the_project_dir(project, tmp_path) -> None:
    pdir, _work = project
    (pdir / "media-staging").mkdir()
    release = _release(tmp_path)
    materialise(pdir, git("rev-parse", "HEAD", cwd=pdir / "repo"), release,
                made=("media-staging",))
    assert not os.path.lexists(release / "media-staging")


@pytest.mark.parametrize("entry", ["foo-staging", "app.db-staging"])
def test_a_project_entry_named_staging_is_refused(project, tmp_path, entry) -> None:
    """As a bundle may not ship one: staging would take it for its copy."""
    pdir, _work = project
    (pdir / entry).mkdir()
    release = _release(tmp_path)
    with pytest.raises(GitRefError, match=f"{entry}: the -staging suffix is reserved"):
        materialise(pdir, git("rev-parse", "HEAD", cwd=pdir / "repo"), release)
    assert not os.path.lexists(release / "repo")


def test_the_suffix_only_counts_at_the_project_top(project, tmp_path) -> None:
    """A commit's own names are nested under repo/, as a bundle's nested
    names are allowed."""
    pdir, work = project
    sha = _push(pdir, work, {"cache-staging/x": "nested is fine"})
    release = _release(tmp_path)
    materialise(pdir, sha, release)
    assert (release / "repo" / "cache-staging" / "x").read_text() == "nested is fine"
