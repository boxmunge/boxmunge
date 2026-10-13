"""stage/promote keep the production release so rollback stays truthful.

stage installs the staged release into the shared project dir; the
production release it displaced is kept until promote (it becomes the
previous release, the rollback target) or unstage.
"""
from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import patch

from boxmunge.backup import BackupKind
from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.promote_cmd import run_promote
from boxmunge.commands.rollback import find_rollback_target, run_rollback
from boxmunge.commands.stage_cmd import run_stage
from boxmunge.project_registry import add_project
from boxmunge.state import read_state

from tests.bundle_helpers import place_bundle

V1 = "2026-10-13T090000000000"
V2 = "2026-10-13T100000000000"


@contextmanager
def _docker():
    with patch("boxmunge.commands.deploy.compose_up"), \
            patch("boxmunge.commands.deploy.caddy_reload"), \
            patch("boxmunge.commands.stage_cmd.compose_up"), \
            patch("boxmunge.commands.stage_cmd.caddy_reload"), \
            patch("boxmunge.commands.unstage_cmd.compose_down"), \
            patch("boxmunge.commands.unstage_cmd.caddy_reload"):
        yield


def _prod_v1_staged_v2(paths):
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1, files={"VERSION": "v1\n"})
    place_bundle(paths, timestamp=V2, files={"VERSION": "v2\n"})
    with _docker():
        assert run_deploy("myapp", paths, ref=V1) == 0
        assert run_stage("myapp", paths, ref=V2) == 0
    return paths.project_dir("myapp")


def test_stage_records_the_staged_bundle_ref(paths) -> None:
    _prod_v1_staged_v2(paths)
    assert read_state(paths.project_staging_state("myapp"))["ref"] == f"myapp-{V2}"


def test_prod_deploy_refused_while_a_release_is_staged(paths, capsys) -> None:
    _prod_v1_staged_v2(paths)
    place_bundle(paths, timestamp="2026-10-13T110000000000")
    with _docker():
        assert run_deploy("myapp", paths) == 1
    assert "promote myapp" in capsys.readouterr().err


def test_promote_makes_the_production_release_the_rollback_target(paths) -> None:
    pdir = _prod_v1_staged_v2(paths)
    with _docker():
        assert run_promote("myapp", paths) == 0
    assert (pdir / "VERSION").read_text() == "v2\n"
    state = read_state(paths.project_deploy_state("myapp"))
    assert state["current_ref"] == f"myapp-{V2}"
    assert find_rollback_target(paths, "myapp").ref == f"myapp-{V1}"

    with _docker():
        assert run_rollback("myapp", paths, yes=True) == 0
    assert (pdir / "VERSION").read_text() == "v1\n"


def test_promote_never_deploys_a_newer_inbox_bundle(paths) -> None:
    pdir = _prod_v1_staged_v2(paths)
    place_bundle(paths, timestamp="2026-10-13T110000000000",
                 files={"VERSION": "v3-unstaged\n"})
    with _docker():
        assert run_promote("myapp", paths) == 0
    assert (pdir / "VERSION").read_text() == "v2\n"


def test_first_stage_then_promote_has_no_rollback_target(paths, capsys) -> None:
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1)
    with _docker():
        assert run_stage("myapp", paths) == 0
        assert run_promote("myapp", paths) == 0
        assert run_rollback("myapp", paths, yes=True) == 1
    assert "no previous release" in capsys.readouterr().err


def test_failure_keeping_previous_after_promote_never_lets_unstage_revert(
    paths, capsys,
) -> None:
    """Production already runs the staged release when the kept production
    release is turned into the previous one. If that step fails, the kept
    release must not linger: unstage would put old files under the running
    new release."""
    from boxmunge.commands.unstage_cmd import run_unstage
    from boxmunge.release import has_prestage
    pdir = _prod_v1_staged_v2(paths)
    with _docker(), patch("boxmunge.commands.deploy.prestage_to_previous",
                          side_effect=OSError("disk full")):
        assert run_promote("myapp", paths) == 1
    assert not has_prestage(paths, "myapp")
    assert "rollback" in capsys.readouterr().err
    with _docker():
        assert run_unstage("myapp", paths) == 0
    assert (pdir / "VERSION").read_text() == "v2\n"


def test_promote_snapshots_production_data_with_the_production_manifest(paths) -> None:
    """The snapshot paired with the kept production release must be taken
    with that release's backup config, not the staged one's (which may
    differ, or declare no backups at all)."""
    from tests.bundle_helpers import manifest_text

    taken: list[dict] = []

    def fake_backup(project_name, paths_, _lock_held=False, kind=None, manifest=None):
        assert kind is BackupKind.PREDEPLOY
        taken.append(manifest)
        snap = paths_.project_backups(project_name) / f"{project_name}-p{len(taken)}.tar.gz.age"
        snap.parent.mkdir(parents=True, exist_ok=True)
        snap.write_text("snapshot")
        return 0

    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1, files={"manifest.yml": manifest_text(backup="postgres")})
    place_bundle(paths, timestamp=V2, files={"manifest.yml": manifest_text(backup="none")})
    with _docker(), patch("boxmunge.commands.backup_cmd.run_backup", fake_backup):
        assert run_deploy("myapp", paths, ref=V1) == 0
        assert run_stage("myapp", paths, ref=V2) == 0
        taken.clear()
        assert run_promote("myapp", paths) == 0
    assert len(taken) == 1
    assert taken[0]["backup"]["type"] == "postgres"
    assert find_rollback_target(paths, "myapp").snapshot == "myapp-p1.tar.gz.age"
