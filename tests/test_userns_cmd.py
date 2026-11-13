"""userns commands: root only, under the shim's lock, never from the deploy shell."""
from __future__ import annotations

import fcntl
import os

import pytest

from boxmunge import cli, shell
from boxmunge.commands import userns_cmd
from boxmunge.commands.usage import USAGE
from boxmunge.userns.inventory import ContainerEntry, Inventory
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


def _lock_file(paths) -> int:
    paths.upgrade_lock.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    return os.open(paths.upgrade_lock, os.O_WRONLY | os.O_CREAT, 0o600)


def test_refuses_without_the_shims_lock(paths) -> None:
    fd = _lock_file(paths)
    try:
        with pytest.raises(SystemExit, match="run this through the shim"):
            userns_cmd.require_upgrade_lock_held(paths, fd)  # the file, not locked
    finally:
        os.close(fd)
    with pytest.raises(SystemExit, match="run this through the shim"):
        userns_cmd.require_upgrade_lock_held(paths, 987)  # no such descriptor


def test_refuses_a_descriptor_on_another_file(paths, tmp_path) -> None:
    fd = _lock_file(paths)
    other = os.open(tmp_path / "other", os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(other, fcntl.LOCK_EX)
        with pytest.raises(SystemExit, match="run this through the shim"):
            userns_cmd.require_upgrade_lock_held(paths, other)
    finally:
        for held in (other, fd):
            os.close(held)


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
    assert ("a userns migration stopped at rebuilt; resume it: sudo /opt/boxmunge/bin/"
            "boxmunge-upgrade userns-migrate" in capsys.readouterr().out)
    save_journal(paths, Journal(FORWARD, "committed", S, fresh_install=True))
    assert userns_cmd.run_check(paths) == 0
    assert "VERDICT: the userns migration is already committed" in capsys.readouterr().out


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


def _container(cid: str, running: bool) -> ContainerEntry:
    return ContainerEntry(cid, cid, "shop", "web", "sha256:i", running, False, "", "", "", "")


@pytest.mark.parametrize("phase", ["started", "prepared", "quiesced"])
def test_check_after_a_pre_switch_journal_runs_the_resume_preflight_with_images(
        paths, monkeypatch, capsys, phase) -> None:
    """A resume before the switch runs phase 0's checks again, images
    included, and refuses on them: the check runs the same ones, on the
    journal's offset and with who was running before a partial quiesce,
    instead of only saying "resume"."""
    earlier = Inventory("overlay2", "", "/var/lib/docker", "29.9.0",
                        containers=[_container("gone", True), _container("web", True)])
    save_journal(paths, Journal(FORWARD, phase, S, inventory=earlier.to_json()))
    fresh = Inventory("overlay2", "", "/var/lib/docker", "29.9.0",
                      containers=[_container("web", False)])  # stopped by the quiesce
    monkeypatch.setattr(userns_cmd, "take_inventory", lambda paths: fresh)
    monkeypatch.setattr(userns_cmd.uo, "allocate_offset", lambda *a: pytest.fail("new offset"))
    calls = []
    monkeypatch.setattr(userns_cmd, "preflight", lambda paths, inv, **kw: calls.append(
        (inv, kw)) or Report(refusals=["shop:1: files in its layers are owned by uid 70000"]))
    assert userns_cmd.run_check(paths) == 0
    (inv, kw), = calls
    assert kw["offset"] == S and kw["direction"] == FORWARD and kw.get("scan_images", True)
    assert {(c.id, c.running) for c in inv.containers} == {("web", True), ("gone", True)}
    out = capsys.readouterr().out.splitlines()
    assert out[0] == (f"a userns migration stopped at {phase}; resume it: sudo /opt/boxmunge/"
                      f"bin/boxmunge-upgrade userns-migrate, or undo it: sudo /opt/boxmunge/"
                      f"bin/boxmunge-upgrade userns-rollback")
    assert "REFUSED: shop:1: files in its layers are owned by uid 70000" in out
    assert out[-1] == "VERDICT: not ready: 1 refusal(s) above"
    assert not any(line.startswith("VERDICT") for line in out[:-1])


@pytest.mark.parametrize("window", ["merged daemon.json, no record yet",
                                    "record, daemon.json put back"])
def test_check_after_an_interrupted_switch_leaves_the_checks_to_the_resume(
        paths, monkeypatch, capsys, window) -> None:
    """The switch writes the merged daemon.json, then the record; undoing it
    writes the original back, then drops the record. A kill in either
    window leaves one without the other, and the resume puts the old daemon
    back before its checks (switch.ensure_prior), which a read-only check
    cannot do: it does not scan."""
    from boxmunge.userns import switch as sw
    from boxmunge.userns.daemon_config import merged_daemon_json
    original = '{"log-driver": "json-file"}'
    (sw.uo.ETC / "docker").mkdir()
    daemon_json = sw.uo.ETC / "docker" / "daemon.json"
    paths.config_file.write_text("hostname: h\nadmin_email: a@b.c\n")
    if window.startswith("merged"):
        daemon_json.write_bytes(merged_daemon_json(original.encode()))
    else:
        daemon_json.write_text(original)
        sw.uo.write_offset_record(paths, S)
    save_journal(paths, Journal(FORWARD, "quiesced", S, daemon_json=original))
    monkeypatch.setattr(userns_cmd, "preflight", lambda *a, **kw: pytest.fail("scanned"))
    assert userns_cmd.run_check(paths) == 0
    out = capsys.readouterr().out.splitlines()
    assert "the switch to the remapped daemon was interrupted" in out[0]
    assert out[-1].startswith("VERDICT: a userns migration stopped at quiesced; resume it: "
                              "sudo /opt/boxmunge/bin/boxmunge-upgrade userns-migrate")
