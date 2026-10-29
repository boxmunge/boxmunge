# SPDX-License-Identifier: Apache-2.0
"""project-forget: drop a registry entry whose project directory is gone."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from boxmunge.commands import project_forget_cmd
from boxmunge.commands.project_forget_cmd import cmd_project_forget, run_project_forget
from boxmunge.project_registry import (
    forget_advice, is_registered, missing_among, read_registry,
)
from tests.test_commands.cve_helpers import make_box


@pytest.fixture(autouse=True)
def as_root(monkeypatch):
    monkeypatch.setattr("boxmunge.commands.project_forget_cmd.running_as_root", lambda: True)
    monkeypatch.setattr("boxmunge.docker_containers.project_volumes", lambda p: [])


def _drifted(tmp_path):
    paths = make_box(tmp_path, projects=("alive",))
    with (paths.state / "projects.txt").open("a") as f:
        f.write("gone\n")
    paths.project_scan_state("gone").parent.mkdir(parents=True, exist_ok=True)
    paths.project_scan_state("gone").write_text("{}")
    paths.project_lock_file("gone").write_text("")
    return paths


def test_missing_among_lists_only_names_without_a_directory(tmp_path):
    paths = _drifted(tmp_path)
    assert missing_among(read_registry(paths).names, paths) == ["gone"]
    assert "project-forget gone" in forget_advice("gone")


def test_forget_drops_the_entry_and_its_state_and_keeps_the_others(tmp_path, capsys):
    paths = _drifted(tmp_path)
    assert run_project_forget("gone", paths) == 0
    assert not is_registered("gone", paths) and is_registered("alive", paths)
    assert not paths.project_scan_state("gone").exists()
    assert "forgotten" in capsys.readouterr().out


def test_forget_refuses_while_the_project_directory_exists(tmp_path, capsys):
    paths = _drifted(tmp_path)
    assert run_project_forget("alive", paths) == 1
    assert is_registered("alive", paths)
    assert "project-delete alive" in capsys.readouterr().err


def test_forget_refuses_while_containers_exist(tmp_path, monkeypatch, capsys):
    paths = _drifted(tmp_path)
    monkeypatch.setattr("boxmunge.docker_containers.project_containers",
                        lambda project: [SimpleNamespace(name="gone-web-1")])
    assert run_project_forget("gone", paths) == 1
    assert is_registered("gone", paths)
    assert "gone-web-1" in capsys.readouterr().err


def test_forget_of_an_unregistered_name_fails(tmp_path, capsys):
    assert run_project_forget("nope", make_box(tmp_path)) == 1
    assert "not registered" in capsys.readouterr().err


def test_cli_entry_exits_with_the_result(tmp_path, monkeypatch):
    paths = _drifted(tmp_path)
    monkeypatch.setattr("boxmunge.commands.project_forget_cmd.BoxPaths", lambda: paths)
    with pytest.raises(SystemExit) as exc:
        cmd_project_forget(["gone"])
    assert exc.value.code == 0


def test_forget_unlinks_the_lock_files_and_names_the_kept_volumes(tmp_path, monkeypatch, capsys):
    paths = _drifted(tmp_path)
    paths.secrets_locks.mkdir()
    (paths.secrets_locks / "gone.lock").write_text("")
    monkeypatch.setattr("boxmunge.docker_containers.project_volumes",
                        lambda p: ["gone_pgdata"])
    assert run_project_forget("gone", paths) == 0
    assert not paths.project_lock_file("gone").exists()
    assert not (paths.secrets_locks / "gone.lock").exists()
    assert "Docker volumes are kept: gone_pgdata" in capsys.readouterr().out


def test_forget_as_non_root_fails_cleanly(tmp_path, monkeypatch, capsys):
    paths = _drifted(tmp_path)
    monkeypatch.setattr("boxmunge.commands.project_forget_cmd.running_as_root", lambda: False)
    assert run_project_forget("gone", paths) == 1
    assert "operator-only: run it as root" in capsys.readouterr().err
    assert is_registered("gone", paths)


def test_a_deploy_that_wins_the_race_keeps_the_project(tmp_path, monkeypatch, capsys):
    """The directory appears after the caller's first look, before the lock."""
    paths = _drifted(tmp_path)
    real = project_forget_cmd._refusal
    calls = []

    def racing(project, p):
        calls.append(project)
        p.project_dir(project).mkdir()  # a deploy lands just before the check
        return real(project, p)

    monkeypatch.setattr(project_forget_cmd, "_refusal", racing)
    assert run_project_forget("gone", paths) == 1
    assert is_registered("gone", paths)
    assert paths.project_scan_state("gone").exists()
    assert calls == ["gone"]
