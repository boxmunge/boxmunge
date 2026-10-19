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


def _lock_files(paths):
    fds = []
    for path in (paths.upgrade_lock, paths.legacy_upgrade_lock):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fds.append(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600))
    return tuple(fds)


def test_refuses_without_the_shims_locks(paths) -> None:
    fds = _lock_files(paths)
    try:
        with pytest.raises(SystemExit, match="run this through the shim"):
            userns_cmd.require_upgrade_lock_held(paths, fds)  # the files, not locked
        fcntl.flock(fds[0], fcntl.LOCK_EX)
        with pytest.raises(SystemExit, match="run this through the shim"):
            userns_cmd.require_upgrade_lock_held(paths, fds)  # the legacy one is not held
    finally:
        for fd in fds:
            os.close(fd)
    with pytest.raises(SystemExit, match="run this through the shim"):
        userns_cmd.require_upgrade_lock_held(paths, (987, 986))  # no such descriptors


def test_refuses_a_descriptor_on_another_file(paths, tmp_path) -> None:
    fds = _lock_files(paths)
    other = os.open(tmp_path / "other", os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        for fd in (other, fds[1]):
            fcntl.flock(fd, fcntl.LOCK_EX)
        with pytest.raises(SystemExit, match="run this through the shim"):
            userns_cmd.require_upgrade_lock_held(paths, (other, fds[1]))
    finally:
        for fd in (other, *fds):
            os.close(fd)


def test_accepts_the_locks_the_shim_handed_down(paths) -> None:
    fds = _lock_files(paths)
    try:
        for fd in fds:
            fcntl.flock(fd, fcntl.LOCK_EX)  # the shim's open file descriptions
        userns_cmd.require_upgrade_lock_held(paths, fds)
    finally:
        for fd in fds:
            os.close(fd)


def test_check_reports_a_journal_instead_of_scanning(paths, monkeypatch, capsys) -> None:
    monkeypatch.setattr(userns_cmd, "preflight", lambda *a, **kw: pytest.fail("scanned"))
    save_journal(paths, Journal(FORWARD, "rebuilt", S))
    assert userns_cmd.run_check(paths) == 0
    assert ("a userns migration stopped at rebuilt; resume it: sudo /opt/boxmunge/bin/"
            "boxmunge-upgrade userns-migrate" in capsys.readouterr().out)
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


@pytest.mark.parametrize("trouble", ["remap", "journal", "daemon"])
def test_check_always_ends_with_a_verdict_and_exits_0(paths, monkeypatch, capsys,
                                                      trouble) -> None:
    monkeypatch.setattr(userns_cmd.os, "geteuid", lambda: 0)
    monkeypatch.setattr(userns_cmd, "BoxPaths", lambda: paths)
    monkeypatch.setattr(userns_cmd, "host_ids", lambda: set())
    if trouble == "remap":
        def boom(*a):
            raise userns_cmd.uo.RemapError("boxmunge-remap already has other subordinate ids")
        monkeypatch.setattr(userns_cmd.uo, "allocate_offset", boom)
    elif trouble == "journal":
        paths.upgrade_root.mkdir(mode=0o700)
        paths.userns_journal.write_text("not json")
    else:
        def down(paths):
            raise userns_cmd.DockerError("Cannot connect to the Docker daemon")
        monkeypatch.setattr(userns_cmd, "take_inventory", down)
    with pytest.raises(SystemExit) as e:
        userns_cmd.cmd_userns(["check"])
    out = capsys.readouterr().out
    assert e.value.code == 0 and "REFUSED: the check could not run to the end" in out
    assert out.rstrip().endswith("VERDICT: not ready: 1 refusal(s) above")


def test_check_reports_a_commit_stopped_part_way(paths, capsys) -> None:
    save_journal(paths, Journal(FORWARD, "applied", S, items={"commit-before": "1"}))
    userns_cmd.run_check(paths)
    assert "finish it: sudo /opt/boxmunge/bin/boxmunge-upgrade userns-commit" in capsys.readouterr().out
