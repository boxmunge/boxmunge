"""The y/N confirmation: refused cleanly without a terminal, naming --yes."""
from __future__ import annotations

import ast
import importlib
import io
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from boxmunge.commands.confirm import confirm
from boxmunge.paths import BoxPaths

SRC = Path(__file__).resolve().parents[2] / "src" / "boxmunge"


class _NoTerminal(io.StringIO):
    """stdin of `ssh box cmd` with the session left open: reading blocks forever."""

    def readline(self, *_a: object) -> str:
        raise AssertionError("read stdin: this would hang over ssh")

    read = readline


class _Terminal(io.StringIO):
    def isatty(self) -> bool:
        return True


@pytest.fixture
def no_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", _NoTerminal())


def _terminal(monkeypatch: pytest.MonkeyPatch, typed: str) -> None:
    monkeypatch.setattr("sys.stdin", _Terminal(typed))


class TestConfirm:
    def test_no_terminal_refuses_without_reading(self, no_terminal: None, capsys) -> None:
        assert confirm("pause") is False
        err = capsys.readouterr().err
        assert "ERROR:" in err and "'pause'" in err and "--yes" in err
        assert "Nothing was changed" in err

    def test_closed_stdin_refuses(self, monkeypatch, capsys) -> None:
        monkeypatch.setattr("sys.stdin", io.StringIO(""))
        assert confirm("recover") is False
        assert "--yes" in capsys.readouterr().err

    def test_no_stdin_at_all_refuses(self, monkeypatch, capsys) -> None:
        monkeypatch.setattr("sys.stdin", None)
        assert confirm("restore") is False
        assert "--yes" in capsys.readouterr().err

    def test_terminal_y_proceeds(self, monkeypatch) -> None:
        _terminal(monkeypatch, "y\n")
        assert confirm("pause") is True

    @pytest.mark.parametrize("typed", ["n\n", "\n", "yes please\n"])
    def test_terminal_anything_else_aborts(self, monkeypatch, capsys, typed: str) -> None:
        _terminal(monkeypatch, typed)
        assert confirm("pause") is False
        assert "Aborted." in capsys.readouterr().out

    def test_terminal_eof_aborts(self, monkeypatch, capsys) -> None:
        _terminal(monkeypatch, "")          # Ctrl-D at the prompt
        assert confirm("pause") is False
        assert "Aborted." in capsys.readouterr().out


def test_every_prompt_goes_through_confirm() -> None:
    """A bare input() outside the helper (and the deploy shell's own REPL)
    is the EOFError/hang this module exists to prevent."""
    allowed = {SRC / "commands" / "confirm.py", SRC / "shell.py"}
    offenders = [
        f"{p.relative_to(SRC)}:{node.lineno}"
        for p in SRC.rglob("*.py") if p not in allowed
        for node in ast.walk(ast.parse(p.read_text()))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id == "input"
    ]
    assert offenders == []


@pytest.mark.parametrize("module,entry,run,args", [
    ("pause_cmd", "cmd_pause", "run_pause", ["myapp", "--yes"]),
    ("resume_cmd", "cmd_resume", "run_resume", ["myapp", "--yes"]),
    ("recover_cmd", "cmd_recover", "run_recover", ["myapp", "--yes"]),
    ("rollback", "cmd_rollback", "run_rollback", ["myapp", "--yes"]),
    ("restore", "cmd_restore", "run_restore", ["myapp", "--yes"]),
    ("project_delete_cmd", "cmd_project_delete", "run_project_delete", ["myapp", "--yes"]),
    ("inbox_cmd", "cmd_inbox", "run_inbox_clean", ["clean", "myapp", "--yes"]),
])
def test_every_prompting_command_accepts_yes(module, entry, run, args) -> None:
    """The deploy shell passes arguments through verbatim (test_shell), so
    what each CLI entry accepts is what `ssh deploy@box <cmd> ... --yes` gets."""
    mod = importlib.import_module(f"boxmunge.commands.{module}")
    with patch.object(mod, run, return_value=0) as called, \
            patch.object(mod, "BoxPaths", create=True), \
            patch("boxmunge.paths.BoxPaths"), pytest.raises(SystemExit) as done:
        getattr(mod, entry)(args)
    assert done.value.code == 0
    assert called.call_args.kwargs["yes"] is True


def _pause_project(tmp_path: Path) -> BoxPaths:
    paths = BoxPaths(root=tmp_path / "bm")
    for d in ["config", "projects/myapp", "state/deploy", "state/health",
              "caddy/sites", "logs"]:
        (paths.root / d).mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text("hostname: t\nadmin_email: a@b\n")
    (paths.project_dir("myapp") / "manifest.yml").write_text(yaml.dump({
        "schema_version": 1, "id": "01TEST", "project": "myapp",
        "source": "bundle", "hosts": ["myapp.test"],
        "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
    }))
    (paths.project_dir("myapp") / "compose.yml").write_text(
        "services:\n  web:\n    image: nginx\n")
    paths.project_caddy_site("myapp").write_text("# original\n")
    return paths


def test_pause_without_terminal_refuses_before_acting(tmp_path, no_terminal, capsys) -> None:
    from boxmunge.commands.pause_cmd import run_pause
    from boxmunge.pause import is_paused
    paths = _pause_project(tmp_path)
    with patch("boxmunge.commands.pause_cmd.compose_stop") as stop, \
            patch("boxmunge.commands.pause_cmd.caddy_reload") as reload:
        assert run_pause("myapp", paths) == 1
    stop.assert_not_called()
    reload.assert_not_called()
    assert not is_paused("myapp", paths)
    assert "--yes" in capsys.readouterr().err


def test_inbox_clean_without_terminal_keeps_the_bundles(tmp_path, no_terminal, capsys) -> None:
    from boxmunge.commands.inbox_cmd import run_inbox_clean
    paths = BoxPaths(root=tmp_path / "bm")
    paths.inbox.mkdir(parents=True)
    bundle = paths.inbox / "myapp-2026-01-01T000000000000.tar.gz"
    bundle.write_bytes(b"x")
    assert run_inbox_clean(paths, project_filter=None) == 1
    assert bundle.exists()
    assert "--yes" in capsys.readouterr().err


def test_mcp_project_delete_without_yes_names_its_own_parameter(tmp_path) -> None:
    from boxmunge import mcp_tools
    with patch("boxmunge.commands.project_delete_cmd.run_project_delete") as run:
        result = mcp_tools._tool_project_delete("myapp", yes=False)
    run.assert_not_called()
    assert result["success"] is False
    assert any("yes=true" in m for m in result["messages"])
