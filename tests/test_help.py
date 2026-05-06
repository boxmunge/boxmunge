"""Tests for help text content."""

from boxmunge.commands.help import HELP_TEXT, AGENT_HELP_TEXT


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
