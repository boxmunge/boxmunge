"""Tests for project-add, project-remove, project-list commands."""

import pytest
from io import StringIO
from unittest.mock import patch

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


class TestCmdProjectRemove:
    def test_unregisters_project(self, paths: BoxPaths) -> None:
        from boxmunge.commands.project_cmd import cmd_project_add, cmd_project_remove
        from boxmunge.project_registry import is_registered
        with patch("boxmunge.commands.project_cmd.BoxPaths", return_value=paths):
            cmd_project_add(["myapp"])
            cmd_project_remove(["myapp"])
        assert not is_registered("myapp", paths)

    def test_unknown_project_exits_1(self, paths: BoxPaths) -> None:
        from boxmunge.commands.project_cmd import cmd_project_remove
        with pytest.raises(SystemExit) as exc:
            with patch("sys.stderr", new_callable=StringIO):
                with patch("boxmunge.commands.project_cmd.BoxPaths", return_value=paths):
                    cmd_project_remove(["ghost"])
        assert exc.value.code == 1


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
