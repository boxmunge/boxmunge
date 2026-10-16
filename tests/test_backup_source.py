"""A backup uses the manifest of the release the containers run (transaction rules)."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from boxmunge.backup_source import backup_source
from boxmunge.commands.backup_cmd import backup_locked
from boxmunge.release import mark_live
from boxmunge.release_txn import advance, open_txn
from tests.bundle_helpers import manifest_text

P = "myapp"


def _manifest(dump: str) -> str:
    return manifest_text(backup="postgres").replace("dump.sh", dump)


@pytest.fixture
def project(paths):
    pdir = paths.project_dir(P)
    (pdir / ".releases" / "previous").mkdir(parents=True)
    (pdir / "manifest.yml").write_text(_manifest("dump-new.sh"))
    (pdir / ".releases" / "previous" / "manifest.yml").write_text(_manifest("dump-old.sh"))
    mark_live(paths, P, "myapp-v2")
    return pdir


def _txn(paths, phase, replaced="myapp-v1", source="bundle"):
    txn = open_txn(paths, P, source=source, ref="myapp-v2", replaced_ref=replaced,
                   staged_id=None, snapshot="")
    for step in txn.phases()[1:txn.phases().index(phase) + 1]:
        txn = advance(paths, P, txn, step)
    return txn


def _dump(src) -> str | None:
    return src.manifest["backup"]["dump_command"] if src.manifest else None


def test_no_install_uses_the_project_dir(paths, project) -> None:
    assert _dump(backup_source(paths, P)) == "dump-new.sh"


@pytest.mark.parametrize("phase,dump", [
    ("committed", "dump-new.sh"), ("previous_kept", "dump-old.sh"),
    ("installed", "dump-old.sh"), ("hook_started", "dump-old.sh")])
def test_per_phase(paths, project, phase, dump) -> None:
    _txn(paths, phase)
    assert _dump(backup_source(paths, P)) == dump


def test_switching_is_ambiguous_and_alerts(paths, project) -> None:
    _txn(paths, "switching")
    src = backup_source(paths, P)
    assert src.manifest is None and src.alert and "switching" in src.skip


def test_first_deploy_has_nothing_running(paths, project) -> None:
    _txn(paths, "installed", replaced=None)
    src = backup_source(paths, P)
    assert src.manifest is None and not src.alert


def test_open_rollback_skips(paths, project) -> None:
    _txn(paths, "installed", source="rollback")
    assert backup_source(paths, P).manifest is None


def test_backup_locked_skips_with_an_alert(paths, project) -> None:
    _txn(paths, "switching")
    sent: list[str] = []
    with patch("boxmunge.commands.backup_cmd._run_backup_inner") as inner, \
            patch("boxmunge.commands.backup_cmd.notify", lambda *a, **k: sent.append(a[1])):
        assert backup_locked(P, paths) == 0
    inner.assert_not_called()
    assert sent


def test_backup_locked_uses_the_running_release(paths, project) -> None:
    _txn(paths, "previous_kept")
    paths.backup_key.parent.mkdir(parents=True, exist_ok=True)
    paths.backup_key.write_text("key")
    with patch("boxmunge.commands.backup_cmd._run_backup_inner", return_value=0) as inner:
        assert backup_locked(P, paths) == 0
    assert inner.call_args.args[2] == "dump-old.sh"


def test_an_unreadable_running_manifest_is_an_error_not_a_skip(paths, project, capsys) -> None:
    """A backup that cannot tell what to dump fails loudly (rc 1), as before."""
    _txn(paths, "previous_kept")
    (project / ".releases" / "previous" / "manifest.yml").write_text("{not yaml")
    with patch("boxmunge.commands.backup_cmd._run_backup_inner") as inner:
        assert backup_locked(P, paths) == 1
    inner.assert_not_called()
    assert "ERROR" in capsys.readouterr().err


def test_an_unreadable_install_record_is_an_error(paths, project, capsys) -> None:
    (project / ".releases" / "install.json").write_text("not json")
    with patch("boxmunge.commands.backup_cmd._run_backup_inner") as inner:
        assert backup_locked(P, paths) == 1
    inner.assert_not_called()
    assert "install.json" in capsys.readouterr().err
