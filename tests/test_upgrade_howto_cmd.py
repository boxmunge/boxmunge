# SPDX-License-Identifier: Apache-2.0
"""`upgrade-howto`: the guide for an upgrade, from the target's signed notes."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge.commands.upgrade_howto_cmd import cmd_upgrade_howto, run_upgrade_howto
from boxmunge.paths import BoxPaths
from tests.upgrade_notes_helpers import entry, notes_bytes

RUN = "boxmunge.commands.upgrade_howto_cmd.subprocess.run"
DISCOVER = "boxmunge.upgrade_target.discover_update"
SHIM = "/opt/boxmunge/bin/boxmunge-upgrade"


def _box(tmp_path: Path, *, version: str = "0.11.8+abc", optout: bool = False) -> BoxPaths:
    paths = BoxPaths(root=tmp_path / "bm")
    paths.config.mkdir(parents=True)
    paths.config_file.write_text("hostname: t\nadmin_email: a@b\n"
                                 + ("version_check:\n  enabled: false\n" if optout else ""))
    paths.version_file.write_text(version + "\n")
    return paths


def _shim(stdout: bytes = b"", stderr: bytes = b"", rc: int = 0):
    return subprocess.CompletedProcess([], rc, stdout=stdout, stderr=stderr)


NOTES = notes_bytes("0.12.0", [entry("0.12.0", "floor", "box", "before")])


def test_howto_prints_the_guide_from_the_shims_verified_notes(tmp_path, capsys) -> None:
    paths = _box(tmp_path)
    with patch(RUN, return_value=_shim(NOTES)) as run:
        assert run_upgrade_howto(paths, "0.12.0", as_json=False) == 0
    argv = run.call_args[0][0]
    assert argv == ["sudo", "-n", str(paths.bin / "boxmunge-upgrade"), "guide", "0.12.0"]
    assert run.call_args[1]["stdin"] is subprocess.DEVNULL
    out = capsys.readouterr().out
    assert out.startswith("Upgrade guide: boxmunge 0.11.8 -> 0.12.0")
    assert "Title of floor" in out


def test_howto_up_to_date_makes_no_sudo_call(tmp_path, capsys) -> None:
    with patch(DISCOVER, return_value={"action": "up_to_date"}), \
         patch(RUN, side_effect=AssertionError("sudo was called")):
        assert run_upgrade_howto(_box(tmp_path), None, as_json=False) == 0
    assert capsys.readouterr().out.strip() == (
        "This box runs 0.11.8, the newest release; nothing to prepare.")


def test_howto_the_installed_release_named_is_up_to_date(tmp_path, capsys) -> None:
    with patch(RUN, side_effect=AssertionError("sudo was called")):
        assert run_upgrade_howto(_box(tmp_path), "0.11.8", as_json=True) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["status"] == "up_to_date" and "already runs 0.11.8" in doc["text"]


def test_howto_an_older_release_is_a_usage_error_naming_what_works(tmp_path, capsys) -> None:
    with patch(RUN, side_effect=AssertionError("sudo was called")):
        assert run_upgrade_howto(_box(tmp_path), "0.11.7", as_json=False) == 2
    err = capsys.readouterr().err
    assert "0.11.8" in err and "--version X.Y.Z" in err and "`upgrade-howto`" in err


def test_howto_opted_out_without_version_exits_2_and_asks_nobody(tmp_path, capsys) -> None:
    with patch(DISCOVER, side_effect=AssertionError("discovery was asked")), \
         patch(RUN, side_effect=AssertionError("sudo was called")):
        assert run_upgrade_howto(_box(tmp_path, optout=True), None, as_json=False) == 2
    err = capsys.readouterr().err
    assert "version_check.enabled: false" in err and "--version X.Y.Z" in err


def test_howto_opted_out_with_version_runs_the_guide(tmp_path) -> None:
    with patch(DISCOVER, side_effect=AssertionError("discovery was asked")), \
         patch(RUN, return_value=_shim(NOTES)):
        assert run_upgrade_howto(_box(tmp_path, optout=True), "0.12.0", as_json=False) == 0


def test_howto_shim_failure_exit_1_quotes_stderr_tail(tmp_path, capsys) -> None:
    stderr = ("x" * 2000 + "\n2026-11-12T00:00:00Z boxmunge-upgrade: FATAL: Release 0.12.0 "
              "publishes no upgrade-notes.json\x1b[0m\n").encode()
    with patch(RUN, return_value=_shim(b"partial", stderr, rc=1)):
        assert run_upgrade_howto(_box(tmp_path), "0.12.0", as_json=False) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "publishes no upgrade-notes.json" in captured.err
    assert "\x1b" not in captured.err and "x" * 500 not in captured.err


def test_howto_sudo_refusal_names_install_sudoers(tmp_path, capsys) -> None:
    with patch(RUN, return_value=_shim(b"", b"sudo: a password is required\n", rc=1)):
        assert run_upgrade_howto(_box(tmp_path), "0.12.0", as_json=False) == 1
    assert "boxmunge-upgrade install-sudoers" in capsys.readouterr().err


def test_howto_unverifiable_notes_exit_1(tmp_path, capsys) -> None:
    with patch(RUN, return_value=_shim(b'{"format": 2}')):
        assert run_upgrade_howto(_box(tmp_path), "0.12.0", as_json=False) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and "format 2" in captured.err


def test_howto_refuses_the_notes_of_another_release(tmp_path, capsys) -> None:
    replayed = notes_bytes("0.11.9", [entry("0.11.9", "old", "box")])
    with patch(RUN, return_value=_shim(replayed)):
        assert run_upgrade_howto(_box(tmp_path), "0.12.0", as_json=False) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "0.11.9, not 0.12.0" in captured.err and "upgrade-check --version 0.12.0" not in (
        captured.out)


def test_howto_json_output(tmp_path, capsys) -> None:
    with patch(RUN, return_value=_shim(NOTES)):
        assert run_upgrade_howto(_box(tmp_path), "0.12.0", as_json=True) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["status"] == "guide" and doc["target"] == "0.12.0"
    assert [e["id"] for e in doc["box_before"]] == ["0.12.0-floor"]


def test_howto_unreadable_version_record_exit_1(tmp_path, capsys) -> None:
    paths = _box(tmp_path)
    paths.version_file.write_text("garbage")
    with patch(RUN, side_effect=AssertionError("sudo was called")):
        assert run_upgrade_howto(paths, "0.12.0", as_json=False) == 1
    assert str(paths.version_file) in capsys.readouterr().err


def test_cmd_parses_version_and_json(tmp_path) -> None:
    with patch("boxmunge.commands.upgrade_howto_cmd.run_upgrade_howto", return_value=0) as run, \
         pytest.raises(SystemExit) as done:
        cmd_upgrade_howto(["--version", "0.12.0", "--json"])
    assert done.value.code == 0
    assert run.call_args[0][1:] == ("0.12.0",) and run.call_args[1] == {"as_json": True}


@pytest.mark.parametrize("args", [["0.12.0"], ["--version"], ["--target", "0.12.0"],
                                  ["--dry-run"]])
def test_cmd_usage_errors_exit_2(args: list[str]) -> None:
    with pytest.raises(SystemExit) as done:
        cmd_upgrade_howto(args)
    assert done.value.code == 2
