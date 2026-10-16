"""Rollback runs in its own transaction; restore waits for open installs."""
from __future__ import annotations

from unittest.mock import patch

from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.restore import restore_locked
from boxmunge.commands.rollback import run_rollback
from boxmunge.project_registry import add_project
from boxmunge.release_txn import load_txn
from tests.bundle_helpers import manifest_text, place_bundle
from tests.txn_helpers import crash_at, docker_off, fake_backups, hook_manifest

V1, V2, V3 = ("2026-10-16T090000000000", "2026-10-16T100000000000",
              "2026-10-16T110000000000")


def _failed_v2(paths):
    """Production v1; v2's hook failed, so its install is open at hook_started."""
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1, files={"VERSION": "v1\n",
                                             "manifest.yml": manifest_text(backup="postgres")})
    place_bundle(paths, timestamp=V2, files={"manifest.yml": hook_manifest("false", "postgres")})
    with docker_off(), fake_backups([]):
        assert run_deploy("myapp", paths, ref=V1) == 0
        assert run_deploy("myapp", paths, ref=V2) == 1


def test_rollback_from_an_open_install_restores_code_and_snapshot(paths) -> None:
    _failed_v2(paths)
    restored: list[tuple] = []
    with docker_off(), patch("boxmunge.commands.rollback.restore_locked",
                             lambda p, pa, snapshot, txn=None: restored.append((snapshot, txn)) or 0):
        assert run_rollback("myapp", paths, yes=True) == 0
    assert (paths.project_dir("myapp") / "VERSION").read_text() == "v1\n"
    assert restored[0][0] == "myapp-p1.tar.gz.age" and restored[0][1] is not None
    assert load_txn(paths, "myapp") is None
    assert not (paths.project_releases("myapp") / "previous").exists()


def test_rollback_refused_before_hook_started(paths, capsys) -> None:
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1)
    place_bundle(paths, timestamp=V2)
    with docker_off():
        assert run_deploy("myapp", paths, ref=V1) == 0
        assert crash_at("txn.installed", lambda: run_deploy("myapp", paths, ref=V2)) == 137
        assert run_rollback("myapp", paths, yes=True) == 1
    assert "nothing to roll back" in capsys.readouterr().err


def test_interrupted_rollback_resumes_without_a_second_restore(paths) -> None:
    _failed_v2(paths)
    restored: list[str] = []
    fake = lambda p, pa, snapshot, txn=None: restored.append(snapshot) or 0  # noqa: E731
    with docker_off(), patch("boxmunge.commands.rollback.restore_locked", fake):
        assert crash_at("rollback.data_restored",
                        lambda: run_rollback("myapp", paths, yes=True)) == 137
        restored.clear()
        assert load_txn(paths, "myapp").source == "rollback"
        assert run_rollback("myapp", paths, yes=True) == 0
    assert restored == []


def test_restore_refused_at_entry_while_an_install_is_open(paths, capsys) -> None:
    _failed_v2(paths)
    (paths.project_backups("myapp") / "myapp-p1.tar.gz.age").write_text("snapshot")
    with patch("boxmunge.commands.restore.compose_down") as down:
        assert restore_locked("myapp", paths, snapshot="myapp-p1.tar.gz.age") == 1
    down.assert_not_called()
    assert f"myapp-{V2}" in capsys.readouterr().err


def test_fix_forward_over_a_rollback_before_data_restored_uses_its_target_snapshot(paths) -> None:
    _failed_v2(paths)
    place_bundle(paths, timestamp=V3, files={"VERSION": "v3\n",
                                             "manifest.yml": manifest_text(backup="postgres")})
    taken: list[dict] = []
    with docker_off(), fake_backups(taken), \
            patch("boxmunge.commands.rollback.restore_locked", lambda *a, **k: 0):
        assert crash_at("rollback.installed", lambda: run_rollback("myapp", paths, yes=True)) == 137
        assert run_deploy("myapp", paths, ref=V3) == 0
    assert taken == []
    meta = (paths.project_releases("myapp") / "previous.json").read_text()
    assert f'"ref": "myapp-{V1}"' in meta and "myapp-p1.tar.gz.age" in meta


def test_fix_forward_over_a_rollback_after_data_restored_takes_a_new_snapshot(paths) -> None:
    _failed_v2(paths)
    place_bundle(paths, timestamp=V3, files={"manifest.yml": manifest_text(backup="postgres")})
    taken: list[dict] = []
    with docker_off(), fake_backups(taken), \
            patch("boxmunge.commands.rollback.restore_locked", lambda *a, **k: 0):
        assert crash_at("rollback.data_restored",
                        lambda: run_rollback("myapp", paths, yes=True)) == 137
        assert run_deploy("myapp", paths, ref=V3) == 0
    assert len(taken) == 1
    assert "myapp-p1.tar.gz.age" in (paths.project_releases("myapp") / "previous.json").read_text()
