"""Tests for project-add, project-list, project-delete commands."""

import json
import pytest
from io import StringIO
from unittest.mock import patch

from boxmunge.log import _reset_logger
from boxmunge.paths import BoxPaths


class TestCmdProjectAdd:
    def test_registers_project(self, paths: BoxPaths) -> None:
        from boxmunge.commands.project_cmd import cmd_project_add
        from boxmunge.project_registry import is_registered
        with patch("boxmunge.commands.project_cmd.BoxPaths", return_value=paths):
            cmd_project_add(["myapp"])
        assert is_registered("myapp", paths)

    def test_no_args_exits_2(self, paths: BoxPaths) -> None:
        from boxmunge.commands.project_cmd import cmd_project_add
        with pytest.raises(SystemExit) as exc:
            with patch("sys.stderr", new_callable=StringIO):
                cmd_project_add([])
        assert exc.value.code == 2

    def test_invalid_name_exits_2(self, paths: BoxPaths) -> None:
        from boxmunge.commands.project_cmd import cmd_project_add
        with pytest.raises(SystemExit) as exc:
            with patch("sys.stderr", new_callable=StringIO):
                with patch("boxmunge.commands.project_cmd.BoxPaths", return_value=paths):
                    cmd_project_add(["BAD!"])
        assert exc.value.code == 2


class TestCmdProjectList:
    def test_lists_registered_projects(self, paths: BoxPaths, capsys) -> None:
        from boxmunge.commands.project_cmd import cmd_project_add, cmd_project_list
        with patch("boxmunge.commands.project_cmd.BoxPaths", return_value=paths):
            cmd_project_add(["alpha"])
            cmd_project_add(["beta"])
            cmd_project_list([])
        output = capsys.readouterr().out
        assert "alpha" in output
        assert "beta" in output

    def test_empty_registry_shows_message(self, paths: BoxPaths, capsys) -> None:
        from boxmunge.commands.project_cmd import cmd_project_list
        with patch("boxmunge.commands.project_cmd.BoxPaths", return_value=paths):
            cmd_project_list([])
        output = capsys.readouterr().out
        assert "No projects registered" in output


class TestCmdProjectDelete:
    def test_cleans_up_registry_when_only_registered(self, paths: BoxPaths) -> None:
        """project-delete must remove the registry entry even when project_dir absent."""
        from boxmunge.commands.project_cmd import cmd_project_add
        from boxmunge.commands.project_delete_cmd import run_project_delete
        from boxmunge.project_registry import is_registered

        with patch("boxmunge.commands.project_cmd.BoxPaths", return_value=paths):
            cmd_project_add(["solo"])
        assert is_registered("solo", paths)

        rc = run_project_delete("solo", paths, yes=True)
        assert rc == 0
        assert not is_registered("solo", paths)

    def test_unknown_project_exits_1(self, paths: BoxPaths) -> None:
        from boxmunge.commands.project_delete_cmd import run_project_delete
        rc = run_project_delete("ghost", paths, yes=True)
        assert rc == 1


def _read_log_entries(paths: BoxPaths) -> list[dict]:
    if not paths.log_file.exists():
        return []
    return [
        json.loads(line)
        for line in paths.log_file.read_text().strip().splitlines()
        if line
    ]


class TestProjectAddLogging:
    def setup_method(self):
        _reset_logger()

    def teardown_method(self):
        _reset_logger()

    def test_project_add_logs_registration(self, paths: BoxPaths) -> None:
        from boxmunge.commands.project_cmd import cmd_project_add
        with patch("boxmunge.commands.project_cmd.BoxPaths", return_value=paths):
            cmd_project_add(["myapp"])
        entries = [e for e in _read_log_entries(paths)
                   if e.get("component") == "project-add"]
        assert len(entries) == 1
        entry = entries[0]
        assert entry["project"] == "myapp"
        assert "registered" in entry["msg"].lower()


class TestProjectDeleteLogging:
    def setup_method(self):
        _reset_logger()

    def teardown_method(self):
        _reset_logger()

    def test_project_delete_uses_project_delete_component(
        self, paths: BoxPaths,
    ) -> None:
        """Component must match CLI verb (was 'delete', now 'project-delete')."""
        from boxmunge.commands.project_cmd import cmd_project_add
        from boxmunge.commands.project_delete_cmd import run_project_delete
        with patch("boxmunge.commands.project_cmd.BoxPaths", return_value=paths):
            cmd_project_add(["solo"])
        run_project_delete("solo", paths, yes=True)
        entries = [e for e in _read_log_entries(paths)
                   if e.get("component") == "project-delete"]
        assert len(entries) == 1
        # No legacy "delete" component.
        assert all(e.get("component") != "delete" for e in _read_log_entries(paths))
