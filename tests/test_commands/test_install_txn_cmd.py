"""boxmunge-server install-txn <project> --drop: the way out of a stale record."""
from __future__ import annotations

import sys

import pytest

from boxmunge import cli
from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.install_txn_cmd import run_drop
from boxmunge.paths import BoxPaths
from boxmunge.project_registry import add_project
from boxmunge.release import mark_live
from boxmunge.release_txn import load_txn, txn_path
from tests.bundle_helpers import place_bundle
from tests.txn_helpers import docker_off, hook_manifest

V1, V2 = "2026-10-16T090000000000", "2026-10-16T100000000000"
P = "myapp"


@pytest.fixture
def failed_v2(paths):
    add_project(P, paths)
    place_bundle(paths, timestamp=V1)
    place_bundle(paths, timestamp=V2, files={"manifest.yml": hook_manifest("false")})
    with docker_off():
        assert run_deploy(P, paths, ref=V1) == 0
        assert run_deploy(P, paths, ref=V2) == 1
    return paths


def test_drop_refuses_an_install_that_is_not_stale(failed_v2, capsys) -> None:
    assert run_drop(P, failed_v2) == 1
    assert load_txn(failed_v2, P) is not None
    err = capsys.readouterr().err
    assert "not stale" in err and "rollback myapp" in err


def test_drop_removes_a_stale_record_and_its_superseded_previous(failed_v2) -> None:
    rel = failed_v2.project_releases(P)
    (rel / "previous.superseded").mkdir()
    mark_live(failed_v2, P, "myapp-from-an-older-boxmunge")
    assert run_drop(P, failed_v2) == 0
    assert not txn_path(failed_v2, P).exists()
    assert not (rel / "previous.superseded").exists()
    assert (rel / "previous").is_dir()


def test_drop_removes_an_unreadable_record(failed_v2) -> None:
    txn_path(failed_v2, P).write_text("not json")
    assert run_drop(P, failed_v2) == 0
    assert not txn_path(failed_v2, P).exists()


def test_drop_with_no_record(paths, capsys) -> None:
    add_project(P, paths)
    assert run_drop(P, paths) == 1
    assert "No install record" in capsys.readouterr().err


def _main(argv, monkeypatch) -> int:
    monkeypatch.setattr(sys, "argv", ["boxmunge", *argv])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    return exc.value.code


def test_cli_requires_drop(paths, monkeypatch, capsys) -> None:
    monkeypatch.setattr(BoxPaths.__init__, "__defaults__", (paths.root,))
    assert _main(["install-txn", P], monkeypatch) == 2
    assert "--drop" in capsys.readouterr().err


def test_cli_drop_reaches_the_command(paths, monkeypatch) -> None:
    from boxmunge.commands import install_txn_cmd
    monkeypatch.setattr(BoxPaths.__init__, "__defaults__", (paths.root,))
    called: list[str] = []
    monkeypatch.setattr(install_txn_cmd, "run_drop", lambda p, _paths: called.append(p) or 0)
    assert _main(["install-txn", P, "--drop"], monkeypatch) == 0
    assert called == [P]


def test_not_in_the_deploy_shell() -> None:
    """Dropping the record is the operator's call, after checking production."""
    from boxmunge.shell import ALLOWED_COMMANDS
    assert "install-txn" not in ALLOWED_COMMANDS
