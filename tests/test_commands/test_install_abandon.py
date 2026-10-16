"""--abandon undoes an install before its hook ran, touching no data."""
from __future__ import annotations

import pytest

from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.install_abandon import run_abandon
from boxmunge.project_registry import add_project
from boxmunge.release_txn import load_txn
from tests.bundle_helpers import place_bundle, tree_snapshot
from tests.txn_helpers import crash_at, docker_off, hook_manifest

V1, V2 = "2026-10-16T090000000000", "2026-10-16T100000000000"


def _prod_v1(paths):
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1, files={"VERSION": "v1\n"})
    with docker_off():
        assert run_deploy("myapp", paths, ref=V1) == 0
    return paths.project_dir("myapp")


@pytest.mark.parametrize("point", ["txn.committed", "txn.previous_kept", "txn.installed"])
def test_abandon_puts_everything_back(paths, point) -> None:
    pdir = _prod_v1(paths)
    before = {k: v for k, v in tree_snapshot(pdir).items()}
    place_bundle(paths, timestamp=V2, files={"VERSION": "v2\n"})
    with docker_off() as up:
        assert crash_at(point, lambda: run_deploy("myapp", paths, ref=V2)) == 137
        up.reset_mock()
        assert run_abandon("myapp", paths) == 0
        up.assert_not_called()
    assert load_txn(paths, "myapp") is None
    after = tree_snapshot(pdir)
    assert {k: v for k, v in after.items() if not k.startswith(".releases/retained")} == before


def test_abandon_refused_from_hook_started(paths, capsys) -> None:
    _prod_v1(paths)
    place_bundle(paths, timestamp=V2, files={"manifest.yml": hook_manifest("false")})
    with docker_off():
        run_deploy("myapp", paths, ref=V2)
        assert run_abandon("myapp", paths) == 1
    err = capsys.readouterr().err
    assert "the pre-deploy hook may have changed data" in err and "rollback myapp" in err


def test_abandon_of_a_first_deploy_removes_its_code(paths) -> None:
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1, files={"VERSION": "v1\n"})
    with docker_off():
        assert crash_at("txn.installed", lambda: run_deploy("myapp", paths, ref=V1)) == 137
        assert run_abandon("myapp", paths) == 0
    pdir = paths.project_dir("myapp")
    assert not (pdir / "manifest.yml").exists() and not (pdir / "VERSION").exists()
    assert not (paths.project_releases("myapp") / "live.json").exists()


def test_abandon_with_nothing_open(paths, capsys) -> None:
    _prod_v1(paths)
    assert run_abandon("myapp", paths) == 1
    assert "nothing to abandon" in capsys.readouterr().err
