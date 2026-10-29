# SPDX-License-Identifier: Apache-2.0
"""Doctor, health and the upgrade report root-made deploy directories and
registry entries with no project directory."""
from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from boxmunge import deploy_dirs, fs_nofollow
from boxmunge.commands.doctor import run_doctor
from boxmunge.commands.upgrade_cmd import run_upgrade
from boxmunge.health_checks.registry import check_registry_drift
from boxmunge.paths import BoxPaths
from boxmunge.version import write_installed_version
from tests.test_commands.cve_helpers import make_box

pytestmark = pytest.mark.skipif(os.getuid() == 0, reason="root can write a 0555 directory")


@pytest.fixture
def as_root_with_deploy(monkeypatch):
    ids = (os.getuid() + 4242, os.getgid())
    for module in (deploy_dirs, fs_nofollow):
        monkeypatch.setattr(module, "running_as_root", lambda: True)
        monkeypatch.setattr(module, "deploy_ids", lambda: ids)
    monkeypatch.setattr(os, "getgrouplist", lambda user, gid: [gid])
    monkeypatch.setattr(os, "fchown", lambda fd, u, g: os.fchmod(fd, 0o775))
    monkeypatch.setattr(os, "chown", lambda *a, **k: None)


def _doctor(paths, capsys):
    import json
    with patch("shutil.which", return_value=None):
        run_doctor(paths, as_json=True)
    return {r["name"]: r for r in json.loads(capsys.readouterr().out)}


def test_doctor_fails_with_the_exact_fix_for_a_root_made_scans_dir(
    tmp_path, as_root_with_deploy, capsys, docker_down,
):
    paths = make_box(tmp_path)
    (paths.state / "scans").mkdir()
    (paths.state / "scans").chmod(0o555)
    result = _doctor(paths, capsys)["Deploy can write state/scans"]
    assert result["status"] == "FAIL"
    assert f"sudo chown -R deploy:deploy {paths.state / 'scans'}" in result["detail"]


def test_doctor_passes_when_deploy_can_write(tmp_path, as_root_with_deploy, capsys, docker_down):
    paths = make_box(tmp_path)
    (paths.state / "scans").mkdir()
    (paths.state / "scans").chmod(0o775)
    paths.deploy_state.chmod(0o775)
    assert _doctor(paths, capsys)["Deploy-writable directories"]["status"] == "PASS"


def test_doctor_warns_about_a_registry_entry_without_a_directory(tmp_path, capsys, docker_down):
    paths = make_box(tmp_path)
    with (paths.state / "projects.txt").open("a") as f:
        f.write("gone\n")
    result = _doctor(paths, capsys)["Project gone registered"]
    assert result["status"] == "WARN"
    assert "sudo boxmunge-server project-forget gone" in result["detail"]


def test_health_check_reports_registry_drift(tmp_path):
    paths = make_box(tmp_path)
    assert check_registry_drift(paths).status == "ok"
    with (paths.state / "projects.txt").open("a") as f:
        f.write("gone\n")
    check = check_registry_drift(paths)
    assert check.status == "warn" and "project-forget gone" in check.detail


def test_upgrade_apply_reowns_a_root_made_scans_dir(tmp_path, as_root_with_deploy, capsys):
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
