# SPDX-License-Identifier: Apache-2.0
"""`upgrade-check`: the target release's own readiness check, through the shim."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge.commands.upgrade_check_cmd import cmd_upgrade_check, run_upgrade_check
from boxmunge.paths import BoxPaths
from tests.test_upgrade_check_result import finding, k3, readiness

RUN = "boxmunge.commands.upgrade_check_cmd.subprocess.run"
DISCOVER = "boxmunge.upgrade_target.discover_update"


def _box(tmp_path: Path, *, version: str = "0.11.8+abc", optout: bool = False) -> BoxPaths:
    paths = BoxPaths(root=tmp_path / "bm")
    paths.config.mkdir(parents=True)
    paths.config_file.write_text("hostname: t\nadmin_email: a@b\n"
                                 + ("version_check:\n  enabled: false\n" if optout else ""))
    paths.version_file.write_text(version + "\n")
    return paths


def _shim(doc, rc: int, stderr: str = ""):
    stdout = doc if isinstance(doc, str) else json.dumps(doc) + "\n"
    return subprocess.CompletedProcess([], rc, stdout=stdout.encode(), stderr=stderr.encode())


BLOCKED = k3("blocked", reasons=["the readiness check found what blocks the upgrade"],
             readiness=readiness([("app", [finding("project.image_missing", "block",
                                                   "image gone", "prod-deploy app --redeploy")]),
                                  ("web", [])]))


def test_pass_runs_the_shims_check_verb_and_exits_0(tmp_path, capsys) -> None:
    paths = _box(tmp_path)
    with patch(RUN, return_value=_shim(k3(), 0)) as run:
        assert run_upgrade_check(paths, "0.12.0", as_json=False) == 0
    assert run.call_args[0][0] == ["sudo", "-n", str(paths.bin / "boxmunge-upgrade"),
                                   "check", "0.12.0"]
    assert run.call_args[1]["stdin"] is subprocess.DEVNULL
    captured = capsys.readouterr()
    assert captured.out.startswith("Result: PASS (complete)")
    assert "several minutes" in captured.err


def test_exit_code_0_only_on_pass(tmp_path) -> None:
    paths = _box(tmp_path)
    with patch(RUN, return_value=_shim(BLOCKED, 1)):
        assert run_upgrade_check(paths, "0.12.0", as_json=False) == 1
    with patch(RUN, return_value=_shim(k3("cant_verify", "refused", reasons=["busy"],
                                          readiness=None, dry_run=None, prerequisites=[]), 1)):
        assert run_upgrade_check(paths, "0.12.0", as_json=False) == 1
    with patch(RUN, return_value=_shim("", 0)):
        assert run_upgrade_check(paths, "0.12.0", as_json=False) == 1


def test_blocked_renders_every_project_and_the_rule(tmp_path, capsys) -> None:
    with patch(RUN, return_value=_shim(BLOCKED, 1)):
        run_upgrade_check(_box(tmp_path), "0.12.0", as_json=False)
    out = capsys.readouterr().out
    assert "app: blocked" in out and "web: pass, nothing to do" in out
    assert "Fix: prod-deploy app --redeploy" in out
    assert "do not upgrade" in out


def test_json_prints_the_k3_object_again(tmp_path, capsys) -> None:
    with patch(RUN, return_value=_shim(BLOCKED, 1)):
        assert run_upgrade_check(_box(tmp_path), "0.12.0", as_json=True) == 1
    captured = capsys.readouterr()
    doc = json.loads(captured.out)
    assert doc["check"] == 1 and doc["result"] == "blocked"
    assert doc["readiness"]["projects"][0]["findings"][0]["id"] == "project.image_missing"
    assert captured.err == ""


def test_the_shim_dying_early_is_cant_verify_quoting_stderr(tmp_path, capsys) -> None:
    with patch(RUN, return_value=_shim("", 1, "boxmunge-upgrade: FATAL: no systemd-run\n")):
        assert run_upgrade_check(_box(tmp_path), "0.12.0", as_json=False) == 1
    out = capsys.readouterr().out
    assert out.startswith("Result: CAN'T VERIFY (shim)")
    assert "FATAL: no systemd-run" in out


def test_a_verdict_for_another_release_is_cant_verify(tmp_path, capsys) -> None:
    with patch(RUN, return_value=_shim(k3(readiness=readiness(release="0.11.9")), 0)):
        assert run_upgrade_check(_box(tmp_path), "0.12.0", as_json=False) == 1
    assert "0.11.9" in capsys.readouterr().out


def test_opted_out_without_version_exits_2_and_asks_nobody(tmp_path, capsys) -> None:
    with patch(DISCOVER, side_effect=AssertionError("discovery was asked")), \
         patch(RUN, side_effect=AssertionError("sudo was called")):
        assert run_upgrade_check(_box(tmp_path, optout=True), None, as_json=True) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "version_check.enabled: false" in captured.err and "--version" in captured.err


def test_the_newest_from_discovery_is_checked(tmp_path) -> None:
    with patch(DISCOVER, return_value={"action": "upgrade", "version": "0.12.0"}), \
         patch(RUN, return_value=_shim(k3(), 0)) as run:
        assert run_upgrade_check(_box(tmp_path), None, as_json=False) == 0
    assert run.call_args[0][0][-1] == "0.12.0"


def test_an_up_to_date_box_has_nothing_to_check(tmp_path, capsys) -> None:
    with patch(DISCOVER, return_value={"action": "up_to_date"}), \
         patch(RUN, side_effect=AssertionError("sudo was called")):
        assert run_upgrade_check(_box(tmp_path), None, as_json=False) == 2
    err = capsys.readouterr().err
    assert "newest release" in err and "`upgrade-howto`" in err


@pytest.mark.parametrize("version", ["0.11.8", "0.11.7"])
def test_a_release_not_newer_than_the_box_is_refused(tmp_path, capsys, version) -> None:
    with patch(RUN, side_effect=AssertionError("sudo was called")):
        assert run_upgrade_check(_box(tmp_path), version, as_json=False) == 2
    err = capsys.readouterr().err
    assert "already runs 0.11.8" in err and "--version X.Y.Z" in err


def test_a_pre_release_box_checks_its_release(tmp_path) -> None:
    with patch(RUN, return_value=_shim(k3(installed="0.12.0-rc.1"), 0)):
        assert run_upgrade_check(_box(tmp_path, version="0.12.0-rc.1"), "0.12.0",
                                 as_json=False) == 0


def test_cmd_parses_version_and_json() -> None:
    with patch("boxmunge.commands.upgrade_check_cmd.run_upgrade_check", return_value=1) as run, \
         pytest.raises(SystemExit) as done:
        cmd_upgrade_check(["--json", "--version", "0.12.0"])
    assert done.value.code == 1
    assert run.call_args[0][1:] == ("0.12.0",) and run.call_args[1] == {"as_json": True}


@pytest.mark.parametrize("args", [["0.12.0"], ["--version"], ["--force"], ["--dry-run"]])
def test_cmd_usage_errors_exit_2(args: list[str]) -> None:
    with pytest.raises(SystemExit) as done:
        cmd_upgrade_check(args)
    assert done.value.code == 2
