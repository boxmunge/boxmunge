"""A bundle deploy runs inside an install transaction (closing table)."""
from __future__ import annotations

from unittest.mock import patch

from boxmunge.commands.deploy import run_deploy
from boxmunge.docker_run import DockerError
from boxmunge.project_registry import add_project
from boxmunge.release_txn import load_txn
from boxmunge.state import read_state
from tests.bundle_helpers import manifest_text, place_bundle, tree_snapshot
from tests.txn_helpers import docker_off, fake_backups, hook_manifest

V1, V2 = "2026-10-16T090000000000", "2026-10-16T100000000000"


def _prod_v1(paths, backup="postgres"):
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1, files={"VERSION": "v1\n",
                                             "manifest.yml": manifest_text(backup=backup)})
    with docker_off():
        assert run_deploy("myapp", paths, ref=V1) == 0
    return paths.project_dir("myapp")


def test_success_closes_the_transaction_and_keeps_the_previous_release(paths) -> None:
    pdir = _prod_v1(paths)
    place_bundle(paths, timestamp=V2, files={"VERSION": "v2\n",
                                             "manifest.yml": manifest_text(backup="postgres")})
    taken: list[dict] = []
    with docker_off(), fake_backups(taken):
        assert run_deploy("myapp", paths, ref=V2) == 0
    assert load_txn(paths, "myapp") is None
    assert (pdir / "VERSION").read_text() == "v2\n"
    prev = paths.project_releases("myapp")
    assert (prev / "previous" / "VERSION").read_text() == "v1\n"
    assert '"data_snapshot": "myapp-p1.tar.gz.age"' in (prev / "previous.json").read_text()
    assert not (prev / "previous.superseded").exists()


def test_keep_failure_closes_and_changes_nothing(paths, capsys) -> None:
    """Review Focus 4 at the command level."""
    pdir = _prod_v1(paths, backup="none")
    place_bundle(paths, timestamp=V2, files={"VERSION": "v2\n"})
    before = tree_snapshot(pdir)
    with docker_off(), patch("boxmunge.release_keep.sync_tree",
                             side_effect=OSError(28, "No space left on device")):
        assert run_deploy("myapp", paths, ref=V2) == 1
    assert load_txn(paths, "myapp") is None
    assert tree_snapshot(pdir) == before
    assert "Nothing in the project was changed" in capsys.readouterr().err


def test_install_failure_leaves_it_open_at_previous_kept(paths, capsys) -> None:
    _prod_v1(paths, backup="none")
    place_bundle(paths, timestamp=V2)
    with docker_off(), patch("boxmunge.commands.deploy_tree.install_release",
                             side_effect=OSError("EIO")):
        assert run_deploy("myapp", paths, ref=V2) == 1
    assert load_txn(paths, "myapp").phase == "previous_kept"
    assert "prod-deploy myapp --abandon" in capsys.readouterr().err


def test_hook_failure_leaves_it_open_at_hook_started(paths, capsys) -> None:
    _prod_v1(paths, backup="none")
    place_bundle(paths, timestamp=V2, files={"manifest.yml": hook_manifest("false")})
    with docker_off() as up:
        assert run_deploy("myapp", paths, ref=V2) == 1
        up.reset_mock()
    txn = load_txn(paths, "myapp")
    assert txn.phase == "hook_started"
    err = capsys.readouterr().err
    assert "rollback myapp" in err and "--abandon" not in err


def test_compose_failure_closes_and_records_the_release(paths) -> None:
    _prod_v1(paths, backup="none")
    place_bundle(paths, timestamp=V2)
    with docker_off() as up:
        up.side_effect = DockerError("up failed")
        assert run_deploy("myapp", paths, ref=V2) == 1
    assert load_txn(paths, "myapp") is None
    assert read_state(paths.project_deploy_state("myapp"))["current_ref"] == f"myapp-{V2}"


def test_other_production_starts_refused_mid_install(paths) -> None:
    from boxmunge.commands.upgrade_steps import restart_projects
    _prod_v1(paths, backup="none")
    place_bundle(paths, timestamp=V2, files={"manifest.yml": hook_manifest("false")})
    with docker_off():
        run_deploy("myapp", paths, ref=V2)
    with docker_off() as up, patch("boxmunge.compose_guard.log_error") as logged:
        result = restart_projects(paths, refused=())
    up.assert_not_called()
    assert result.start_refused == ["myapp"]
    assert "is open at phase hook_started" in logged.call_args.args[1]


def test_first_deploy_has_no_keep_and_no_snapshot(paths) -> None:
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1)
    taken: list[dict] = []
    with docker_off(), fake_backups(taken):
        assert run_deploy("myapp", paths, ref=V1) == 0
    assert taken == [] and not (paths.project_releases("myapp") / "previous").exists()
