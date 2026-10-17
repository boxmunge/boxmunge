"""A release's own top-level ``*-staging`` entry is never staging's copy.

Bundles may not ship one (the suffix is reserved), and one a release
installed before that (or an operator made) is neither mounted by staging
nor removed by unstage or promote.
"""
from __future__ import annotations

from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.stage_cmd import run_stage
from boxmunge.commands.unstage_cmd import run_unstage
from boxmunge.project_registry import add_project
from boxmunge.staged_release import has_slot, load_slot, release_dir, slot_dir
from tests.bundle_helpers import SAFE_COMPOSE, place_bundle
from tests.stage_helpers import V1, V2, V3, prod_and_stage, staging_docker_off

FOO = SAFE_COMPOSE + "    volumes: ['./foo:/foo']\n"
MEDIA = SAFE_COMPOSE + "    volumes: ['./media:/m']\n"


def _production_with_code_named_staging(paths):
    """Production as an older boxmunge installed it: its release shipped
    foo-staging/ as code, which production's compose.yml does not mount."""
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1, files={"VERSION": "v1\n"})
    with staging_docker_off():
        assert run_deploy("myapp", paths, ref=V1) == 0
    pdir = paths.project_dir("myapp")
    (pdir / "foo-staging").mkdir()
    (pdir / "foo-staging" / "code.txt").write_text("prod code")
    return pdir


def test_stage_refuses_to_mount_production_code_named_staging(paths, capsys) -> None:
    pdir = _production_with_code_named_staging(paths)
    place_bundle(paths, timestamp=V2, files={"compose.yml": FOO})
    with staging_docker_off() as docker:
        assert run_stage("myapp", paths, ref=V2) == 1
        docker["up"].assert_not_called()
    err = capsys.readouterr().err
    assert f"{pdir / 'foo-staging'}" in err and "not staging's" in err
    assert not has_slot(paths, "myapp")
    assert (pdir / "foo-staging" / "code.txt").read_text() == "prod code"
    with staging_docker_off():
        assert run_unstage("myapp", paths) == 1  # nothing was staged
    assert (pdir / "foo-staging" / "code.txt").read_text() == "prod code"


def test_teardown_never_deletes_a_copy_staging_did_not_create(paths, capsys) -> None:
    """A slot staged before the check (here: its compose.yml rewritten in
    place) mounts ./foo: unstage still leaves production's foo-staging."""
    pdir = prod_and_stage(paths, staged_files={"compose.yml": MEDIA})
    assert load_slot(paths, "myapp").made == ("media-staging",)
    (pdir / "media-staging").mkdir(exist_ok=True)  # the daemon makes it at up
    (pdir / "foo-staging").mkdir()
    (pdir / "foo-staging" / "code.txt").write_text("prod code")
    (release_dir(slot_dir(paths, "myapp")) / "compose.yml").write_text(
        SAFE_COMPOSE + "    volumes: ['./media:/m', './foo:/foo']\n")
    with staging_docker_off():
        assert run_unstage("myapp", paths) == 0
    assert (pdir / "foo-staging" / "code.txt").read_text() == "prod code"
    assert not (pdir / "media-staging").exists()
    assert "not staging's" in capsys.readouterr().out


def test_a_re_stage_keeps_using_the_copy_its_slot_made(paths) -> None:
    pdir = prod_and_stage(paths, staged_files={"compose.yml": MEDIA})
    (pdir / "media-staging").mkdir(exist_ok=True)  # the daemon makes it at up
    place_bundle(paths, timestamp=V3, files={"compose.yml": MEDIA})
    with staging_docker_off():
        assert run_stage("myapp", paths, ref=V3) == 0
        assert load_slot(paths, "myapp").made == ("media-staging",)
        assert (pdir / "media-staging").is_dir()
        assert run_unstage("myapp", paths) == 0
    assert not (pdir / "media-staging").exists()


def test_deploy_refuses_a_bundle_shipping_a_staging_named_entry(paths, capsys) -> None:
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1, files={"foo-staging/code.txt": "code"})
    with staging_docker_off():
        assert run_deploy("myapp", paths, ref=V1) == 1
    err = capsys.readouterr().err
    assert "foo-staging/" in err and "reserved" in err
    assert not (paths.project_dir("myapp") / "foo-staging").exists()
