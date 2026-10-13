"""Tests for help text content."""

import pytest

from boxmunge import cli
from boxmunge.commands.help import AGENT_HELP_TEXT, HELP_TEXT, cmd_help
from boxmunge.commands.usage import USAGE


class TestHelpText:
    def test_help_includes_stage(self) -> None:
        assert "stage" in HELP_TEXT

    def test_help_includes_promote(self) -> None:
        assert "promote" in HELP_TEXT

    def test_help_includes_inbox(self) -> None:
        assert "inbox" in HELP_TEXT

    def test_help_includes_secrets(self) -> None:
        assert "secrets" in HELP_TEXT

    def test_help_does_not_include_import(self) -> None:
        assert "import <bundle>" not in HELP_TEXT

    def test_help_documents_check_all_read_only_flag(self) -> None:
        """Audit H-N3: check-all --read-only must be visible in help."""
        assert "--read-only" in HELP_TEXT
        # The flag belongs to check-all, not somewhere else.
        assert "check-all [--read-only]" in HELP_TEXT

    def test_agent_help_mentions_restricted_shell(self) -> None:
        assert "restricted" in AGENT_HELP_TEXT.lower() or "deploy shell" in AGENT_HELP_TEXT.lower()

    def test_agent_help_does_not_reference_filesystem(self) -> None:
        # Agent help should not tell agents to read files from the filesystem
        assert "/opt/boxmunge/docs/" not in AGENT_HELP_TEXT


def test_agent_help_security_topic_resolves(tmp_path, monkeypatch) -> None:
    """`agent-help security` resolves to SECURITY.md."""
    from boxmunge.commands.help import AGENT_HELP_TOPICS
    assert AGENT_HELP_TOPICS["security"] == "SECURITY.md"


# ---------------------------------------------------------------------------
# Audit D-01: `help <command>` prints that command's usage and never runs it.
# ---------------------------------------------------------------------------

def _poison_all_handlers(monkeypatch) -> None:
    def _boom(args: list[str]) -> None:
        raise AssertionError(f"handler executed with {args!r}")

    for name in list(cli.COMMANDS):
        monkeypatch.setitem(cli.COMMANDS, name, _boom)


def test_every_command_has_a_usage_entry() -> None:
    assert set(USAGE) == set(cli.COMMANDS)


@pytest.mark.parametrize("name", sorted(cli.COMMANDS))
def test_help_for_command_prints_usage_without_running_it(
    name: str, monkeypatch, capsys,
) -> None:
    _poison_all_handlers(monkeypatch)
    with pytest.raises(SystemExit) as exc:
        cmd_help([name])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert out.strip(), f"help {name} printed nothing"
    assert f"boxmunge {name}" in out


def test_help_unknown_command_exits_2(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        cmd_help(["no-such-command"])
    assert exc.value.code == 2
    assert "ERROR:" in capsys.readouterr().err


def test_help_rejects_extra_arguments(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        cmd_help(["status", "extra"])
    assert exc.value.code == 2
