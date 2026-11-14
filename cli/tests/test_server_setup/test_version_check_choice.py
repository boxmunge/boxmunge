# SPDX-License-Identifier: Apache-2.0
"""server-setup explains the version-check service before asking, and lets
a non-interactive install decline it."""

from boxmunge_cli.server_setup import command
from boxmunge_cli.server_setup.args import parse_args
from boxmunge_cli.server_setup.command import installer_args, run_server_setup
from boxmunge_cli.server_setup.version_check_notice import NOTICE

BASE = ["root@203.0.113.5", "--email", "admin@example.com", "--hostname", "box.example.com"]
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl me@example.com"


def test_flag_is_passed_to_the_installer() -> None:
    args = parse_args([*BASE, "--no-version-check"])
    assert args.no_version_check is True
    assert "--no-version-check" in installer_args(args, "box.example.com", KEY)


def test_default_passes_no_flag() -> None:
    args = parse_args(BASE)
    assert args.no_version_check is False
    assert "--no-version-check" not in installer_args(args, "box.example.com", KEY)


def test_explanation_is_shown_before_are_you_sure(monkeypatch, capsys) -> None:
    class Key:
        line = KEY
        def describe(self) -> str:
            return "test key"
    monkeypatch.setattr(command, "detect_ssh_key", lambda _arg: Key())
    monkeypatch.setattr(command, "have_terminal", lambda: True)
    prompts: list[str] = []
    monkeypatch.setattr("builtins.input", lambda p: prompts.append(p) or "n")

    assert run_server_setup(parse_args(BASE)) == 1

    out = capsys.readouterr().out
    assert NOTICE in out
    assert "what it sends" in out.lower() and "If you decline" in out
    assert prompts == ["Are you sure? [y/N] "]


def test_explanation_is_shown_with_yes_too(monkeypatch, capsys) -> None:
    class Key:
        line = KEY
        def describe(self) -> str:
            return "test key"
    monkeypatch.setattr(command, "detect_ssh_key", lambda _arg: Key())

    def stop(*_a, **_k):
        raise command.ReleaseError("stop here")
    monkeypatch.setattr(command, "_fetch_installer", stop)

    assert run_server_setup(parse_args([*BASE, "--yes", "--no-version-check"])) == 1
    out = capsys.readouterr().out
    assert NOTICE in out and "Version check: OFF" in out
