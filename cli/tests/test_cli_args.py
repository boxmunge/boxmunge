# SPDX-License-Identifier: Apache-2.0
"""Argument handling: --help never runs a command; unknown input is an error."""

from pathlib import Path

import pytest

from boxmunge_cli.cli import main
from boxmunge_cli.init_cmd import run_init

COMMANDS = ["init", "bundle", "stage", "promote", "prod-deploy", "status",
            "logs", "mcp-serve", "server-setup"]


def run_cli(argv: list[str]) -> int:
    with pytest.raises(SystemExit) as exc:
        main(argv)
    return exc.value.code


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_remote) -> Path:
    root = tmp_path / "myapp"
    assert run_init(root, server="box.example.com") == 0
    monkeypatch.chdir(root)
    return root


@pytest.mark.parametrize("command", COMMANDS)
@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_help_runs_nothing(project: Path, fake_remote, command: str, flag: str,
                           capsys) -> None:
    before = sorted(p.name for p in project.parent.iterdir())
    assert run_cli([command, flag]) == 0
    assert fake_remote.calls() == []
    assert sorted(p.name for p in project.parent.iterdir()) == before
    assert "usage:" in capsys.readouterr().out


@pytest.mark.parametrize("command", COMMANDS)
def test_unknown_flag_is_a_usage_error(project: Path, fake_remote, command: str,
                                       capsys) -> None:
    required = {"init": ["--server", "box.example.com"],
                "server-setup": ["root@box.example.com", "--email", "a@example.com"]}
    assert run_cli([command, *required.get(command, []), "--no-such-flag"]) == 2
    assert fake_remote.calls() == []
    assert "--no-such-flag" in capsys.readouterr().err


@pytest.mark.parametrize("command", ["stage", "prod-deploy", "promote", "status",
                                     "mcp-serve"])
def test_extra_positionals_are_rejected(project: Path, fake_remote, command: str) -> None:
    assert run_cli([command, "otherapp"]) == 2
    assert fake_remote.calls() == []


def test_typo_flags_are_rejected(project: Path, fake_remote) -> None:
    assert run_cli(["bundle", ".", "--outptu", "x"]) == 2
    assert run_cli(["init", "--sever", "box.example.com"]) == 2


def test_flag_missing_its_value_is_rejected(project: Path) -> None:
    assert run_cli(["bundle", ".", "--output"]) == 2


@pytest.mark.parametrize("value", ["abc", "0", "70000"])
def test_bad_port_is_a_usage_error_not_a_traceback(tmp_path: Path, monkeypatch,
                                                   value: str) -> None:
    monkeypatch.chdir(tmp_path)
    assert run_cli(["init", "--server", "box.example.com", "--port", value]) == 2
    assert not (tmp_path / ".boxmunge").exists()


def test_init_validates_the_config_before_writing(tmp_path: Path, monkeypatch,
                                                  capsys) -> None:
    monkeypatch.chdir(tmp_path)
    assert run_cli(["init", "--server", "bad;host"]) == 1
    assert not (tmp_path / ".boxmunge").exists()
    assert "ERROR:" in capsys.readouterr().err


def test_bundle_defaults_to_the_current_directory(project: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    assert run_cli(["bundle", "--output", str(out)]) == 0
    assert list(out.glob("myapp-*.tar.gz"))


def test_server_setup_has_no_reboot_window(project: Path) -> None:
    assert run_cli(["server-setup", "root@203.0.113.5", "--email", "a@example.com",
                    "--reboot-window", "05:00"]) == 2


def test_server_setup_without_yes_needs_a_terminal(project: Path, fake_remote,
                                                   monkeypatch, capsys) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    rc = run_cli(["server-setup", "root@box.example.com", "--email", "a@example.com"])
    assert rc == 2
    assert "--yes" in capsys.readouterr().err
    assert fake_remote.calls() == []


def test_version(capsys) -> None:
    import boxmunge_cli
    assert run_cli(["--version"]) == 0
    assert boxmunge_cli.__version__ in capsys.readouterr().out
