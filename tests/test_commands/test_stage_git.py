"""Git stage: a slot at a SHA resolved now; production's checkout never moves."""
from __future__ import annotations

import os

import yaml

from boxmunge.commands.stage_cmd import run_stage
from boxmunge.staged_release import building_dir, load_slot, release_dir, slot_dir
from tests.bundle_helpers import place_bundle
from tests.git_helpers import commit, git
from tests.git_project_helpers import git_project
from tests.stage_helpers import staging_docker_off

BUILDS_FROM_REPO = "services:\n  web:\n    build: ./repo\n"


def test_stage_a_while_production_is_at_b(paths, tmp_path) -> None:
    pdir, work = git_project(paths, tmp_path)
    prod_head = git("rev-parse", "HEAD", cwd=pdir / "repo")
    a = commit(work, {"VERSION": "staged\n"}, "staged")
    with staging_docker_off() as docker:
        assert run_stage("myapp", paths) == 0
    meta = load_slot(paths, "myapp")
    assert meta.kind == "git" and meta.ref == a and meta.state == "ready"
    assert meta.bundle_sha256 is None
    release = release_dir(slot_dir(paths, "myapp"))
    assert (release / "repo" / "VERSION").read_text() == "staged\n"
    assert os.readlink(release / "compose.yml") == "repo/compose.yml"
    assert git("rev-parse", "HEAD", cwd=pdir / "repo") == prod_head
    assert git("status", "--porcelain", cwd=pdir / "repo") == ""
    assert docker["up"].call_args.args[0] == release


def test_stage_of_an_unknown_ref_changes_nothing(paths, tmp_path, capsys) -> None:
    git_project(paths, tmp_path)
    with staging_docker_off():
        assert run_stage("myapp", paths, ref="no-such-branch") == 1
    assert load_slot(paths, "myapp") is None
    assert "neither a branch nor a tag" in capsys.readouterr().err


def test_a_dry_run_names_the_sha_and_changes_nothing(paths, tmp_path, capsys) -> None:
    pdir, work = git_project(paths, tmp_path)
    a = commit(work, {"VERSION": "staged\n"}, "staged")
    with staging_docker_off():
        assert run_stage("myapp", paths, dry_run=True) == 0
    assert f"Would stage 'myapp' at {a}" in capsys.readouterr().out
    assert load_slot(paths, "myapp") is None
    assert not os.path.lexists(building_dir(paths, "myapp"))
    assert not os.path.lexists(paths.project_releases("myapp") / "incoming")


def test_a_refused_commit_leaves_nothing(paths, tmp_path, capsys) -> None:
    _pdir, work = git_project(paths, tmp_path)
    os.symlink("/etc", work / "escape")
    commit(work, {}, "escape")
    with staging_docker_off():
        assert run_stage("myapp", paths) == 1
    err = capsys.readouterr().err
    assert "resolves outside the staged release" in err and "Nothing was changed" in err
    assert load_slot(paths, "myapp") is None
    assert not os.path.lexists(building_dir(paths, "myapp"))


def test_a_git_slot_builds_from_its_own_clone(paths, tmp_path) -> None:
    """A git project builds from repo/: in the slot that is the staged clone,
    so the staging base keeps the context relative (it resolves in the
    slot's release) instead of refusing it as boxmunge's own entry."""
    git_project(paths, tmp_path, compose=BUILDS_FROM_REPO,
                files={"Dockerfile": "FROM scratch\n"})
    with staging_docker_off():
        assert run_stage("myapp", paths) == 0
    slot = slot_dir(paths, "myapp")
    web = yaml.safe_load((slot / "compose.staging-base.yml").read_text())["services"]["web"]
    assert web["build"] == "./repo"


def test_restage_replaces_the_git_slot(paths, tmp_path) -> None:
    _pdir, work = git_project(paths, tmp_path)
    commit(work, {"VERSION": "one\n"}, "one")
    with staging_docker_off():
        assert run_stage("myapp", paths) == 0
        first = load_slot(paths, "myapp")
        two = commit(work, {"VERSION": "two\n"}, "two")
        assert run_stage("myapp", paths) == 0
    meta = load_slot(paths, "myapp")
    assert meta.id != first.id and meta.ref == two
    assert (release_dir(slot_dir(paths, "myapp")) / "repo" / "VERSION").read_text() == "two\n"


def test_a_git_stage_leaves_the_inbox_alone(paths, tmp_path) -> None:
    git_project(paths, tmp_path)
    bundle = place_bundle(paths, timestamp="2026-10-16T120000000000")
    with staging_docker_off():
        assert run_stage("myapp", paths) == 0
    assert bundle.exists()
