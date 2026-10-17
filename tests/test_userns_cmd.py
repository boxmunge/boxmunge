"""userns commands: root only, under the shim's lock, never from the deploy shell."""
from __future__ import annotations

import fcntl
import os

import pytest

from boxmunge import cli, shell
from boxmunge.commands import userns_cmd
from boxmunge.commands.usage import USAGE
from boxmunge.userns.journal import FORWARD, ROLLBACK, Journal, save_journal
from boxmunge.userns.preflight import Report

S = 1048576


def test_registered_but_not_reachable_from_the_deploy_shell() -> None:
    assert "userns" in cli.COMMANDS and "userns" in USAGE
    assert "userns" not in shell.ALLOWED_COMMANDS and "userns" in cli.UNWIND_ON_SIGTERM


def test_refuses_a_non_root_caller(monkeypatch, capsys) -> None:
    monkeypatch.setattr(userns_cmd.os, "geteuid", lambda: 1000)
    with pytest.raises(SystemExit) as e:
        userns_cmd.cmd_userns(["migrate"])
    assert e.value.code == 1 and "runs as root" in capsys.readouterr().err


def test_an_unknown_subcommand_is_a_usage_error(capsys) -> None:
    with pytest.raises(SystemExit) as e:
        userns_cmd.cmd_userns(["now"])
    assert e.value.code == 2 and "unknown subcommand" in capsys.readouterr().err


def _lock_file(paths):
    paths.upgrade_lock.parent.mkdir(parents=True, exist_ok=True)
    return os.open(paths.upgrade_lock, os.O_WRONLY | os.O_CREAT, 0o600)


def test_refuses_without_the_shims_lock(paths) -> None:
    fd = _lock_file(paths)
    try:
        with pytest.raises(SystemExit, match="run this through the shim"):
            userns_cmd.require_upgrade_lock_held(paths, fd)  # the file, but not locked
    finally:
        os.close(fd)
    with pytest.raises(SystemExit, match="run this through the shim"):
        userns_cmd.require_upgrade_lock_held(paths, 987)  # no such descriptor


def test_refuses_a_descriptor_on_another_file(paths, tmp_path) -> None:
    os.close(_lock_file(paths))
    other = os.open(tmp_path / "other", os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(other, fcntl.LOCK_EX)
        with pytest.raises(SystemExit, match="run this through the shim"):
            userns_cmd.require_upgrade_lock_held(paths, other)
    finally:
        os.close(other)


def test_accepts_the_lock_the_shim_handed_down(paths) -> None:
    fd = _lock_file(paths)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)  # the shim's open file description
        userns_cmd.require_upgrade_lock_held(paths, fd)
    finally:
        os.close(fd)


def test_check_reports_a_journal_instead_of_scanning(paths, monkeypatch, capsys) -> None:
    monkeypatch.setattr(userns_cmd, "preflight", lambda *a, **kw: pytest.fail("scanned"))
    save_journal(paths, Journal(FORWARD, "rebuilt", S))
    assert userns_cmd.run_check(paths) == 0
    assert "a userns forward is in progress (phase rebuilt)" in capsys.readouterr().out
    save_journal(paths, Journal(FORWARD, "committed", S, fresh_install=True))
    assert userns_cmd.run_check(paths) == 0
    assert "VERDICT: already committed" in capsys.readouterr().out


def test_check_after_a_rollback_runs_the_preflight(paths, monkeypatch, capsys) -> None:
    save_journal(paths, Journal(ROLLBACK, "rolled-back", S))
    monkeypatch.setattr(userns_cmd, "take_inventory", lambda paths: None)
    monkeypatch.setattr(userns_cmd, "preflight",
                        lambda paths, inv, **kw: Report(refusals=["x is wrong"]))
    assert userns_cmd.run_check(paths) == 0  # a report, never a failure
    out = capsys.readouterr().out
    assert f"remap offset: {S}" in out and "REFUSED: x is wrong" in out
