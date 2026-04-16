"""Tests for boxmunge status command."""

from boxmunge.commands.status import run_status
from boxmunge.paths import BoxPaths


class TestRunStatus:
    def test_pre_registered_shown_in_dashboard(self, paths: BoxPaths, capsys) -> None:
        pdir = paths.project_dir("myapp")
        pdir.mkdir(parents=True)
        (pdir / "secrets.env").write_text("KEY=val\n")

        exit_code = run_status(paths)
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "myapp" in captured.out
        assert "PRE-REGISTERED" in captured.out

    def test_pre_registered_shown_in_json(self, paths: BoxPaths, capsys) -> None:
        pdir = paths.project_dir("myapp")
        pdir.mkdir(parents=True)
        (pdir / "secrets.env").write_text("KEY=val\n")

        exit_code = run_status(paths, as_json=True)
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "pre-registered" in captured.out
        assert "PRE-REGISTERED" in captured.out

    def test_empty_projects_dir(self, paths: BoxPaths, capsys) -> None:
        exit_code = run_status(paths)
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "No projects registered" in captured.out
