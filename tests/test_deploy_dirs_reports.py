# SPDX-License-Identifier: Apache-2.0
"""Doctor, health and the upgrade report root-made deploy directories and
registry entries with no project directory."""
from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from boxmunge import deploy_dirs
from boxmunge.commands.doctor import run_doctor
from boxmunge.commands.upgrade_cmd import run_upgrade
from boxmunge.health_checks.registry import check_registry_drift
from boxmunge.paths import BoxPaths
from boxmunge.version import write_installed_version
from tests.test_commands.cve_helpers import make_box

pytestmark = pytest.mark.skipif(os.getuid() == 0, reason="root can write a 0555 directory")


def _doctor(paths, capsys):
    import json
    with patch("shutil.which", return_value=None):
        run_doctor(paths, as_json=True)
    return {r["name"]: r for r in json.loads(capsys.readouterr().out)}


def test_doctor_fails_with_the_exact_fix_for_a_root_made_scans_dir(
    tmp_path, fake_root, capsys, docker_down,
):
    paths = make_box(tmp_path)
    (paths.state / "scans").mkdir()
    (paths.state / "scans").chmod(0o555)
    result = _doctor(paths, capsys)["Deploy can write state/scans"]
    assert result["status"] == "FAIL"
    assert f"sudo chown -R deploy:deploy {paths.state / 'scans'}" in result["detail"]


def test_doctor_passes_when_deploy_can_write(tmp_path, fake_root, capsys, docker_down):
    paths = make_box(tmp_path)
    (paths.state / "scans").mkdir()
    (paths.state / "scans").chmod(0o775)
    paths.deploy_state.chmod(0o775)
    assert _doctor(paths, capsys)["Deploy-writable directories"]["status"] == "PASS"


def test_doctor_warns_about_an_unfinished_removal(tmp_path, capsys, docker_down):
    paths = make_box(tmp_path)
    with (paths.state / "projects.txt").open("a") as f:
        f.write("gone\n")
    (paths.deploy_state / "gone.json").write_text("{}")
    result = _doctor(paths, capsys)["Project gone registered"]
    assert result["status"] == "WARN"
    assert "sudo boxmunge-server project-forget gone" in result["detail"]


def test_doctor_is_quiet_about_a_never_deployed_name(tmp_path, capsys, docker_down):
    paths = make_box(tmp_path)
    with (paths.state / "projects.txt").open("a") as f:
        f.write("pending\n")
    assert "Project pending registered" not in _doctor(paths, capsys)


def test_health_check_reports_an_unfinished_removal_but_not_a_pending_name(tmp_path):
    paths = make_box(tmp_path)
    assert check_registry_drift(paths).status == "ok"
    with (paths.state / "projects.txt").open("a") as f:
        f.write("pending\ngone\n")
    assert check_registry_drift(paths).detail.startswith("awaiting first deploy: gone, pending")
    (paths.deploy_state / "gone.json").write_text("{}")
    check = check_registry_drift(paths)
    assert check.status == "warn" and "project-forget gone" in check.detail
    assert "pending" not in check.detail


def test_upgrade_prints_fail_when_the_chown_does_not_take(tmp_path, fake_root, monkeypatch, capsys):
    paths = BoxPaths(root=tmp_path / "bm")
    for d in ["config", "projects", "state/deploy", "stashes", "logs",
              "caddy/sites", "upgrade-state"]:
        (paths.root / d).mkdir(parents=True)
    paths.config_file.write_text("hostname: test\nadmin_email: t@t\n")
    write_installed_version(paths, "0.2.0", "abc1234")
    (paths.state / "scans").mkdir()
    (paths.state / "scans").chmod(0o555)
    monkeypatch.setattr(os, "fchown", lambda fd, u, g: None)
    with patch("boxmunge.commands.upgrade_cmd.caddy_reload"):
        run_upgrade(paths, apply_only=True)
    cap = capsys.readouterr()
    assert "Gave" not in cap.out
    assert f"FAIL: {paths.state / 'scans'} is still not owned by deploy" in cap.err


def test_upgrade_apply_reowns_a_root_made_scans_dir(tmp_path, fake_root, capsys):
    paths = BoxPaths(root=tmp_path / "bm")
    for d in ["config", "projects", "state/deploy", "stashes", "logs",
              "caddy/sites", "upgrade-state"]:
        (paths.root / d).mkdir(parents=True)
    paths.config_file.write_text("hostname: test\nadmin_email: t@t\n")
    write_installed_version(paths, "0.2.0", "abc1234")
    (paths.state / "scans").mkdir()
    (paths.state / "scans").chmod(0o555)

    with patch("boxmunge.commands.upgrade_cmd.caddy_reload"):
        assert run_upgrade(paths, apply_only=True) == 0

    assert f"Gave {paths.state / 'scans'} to the deploy user" in capsys.readouterr().out
    assert deploy_dirs.unwritable_by_deploy(paths) == []
