# SPDX-License-Identifier: Apache-2.0
"""The version-check explanation is one text, reaches agents and the operator,
and matches the documented facts."""
import importlib.util
import json
from pathlib import Path

from boxmunge.commands.help import AGENT_HELP_TOPICS
from boxmunge.version_check_notice import MCP_INSTRUCTIONS, NOTICE

ROOT = Path(__file__).resolve().parent.parent


def _flat(text: str) -> str:
    return " ".join(text.split())


def test_agent_rules_carry_the_rule_and_the_notice():
    rules = (ROOT / "docs/on-server" / AGENT_HELP_TOPICS["rules"]).read_text()
    assert _flat(NOTICE) in _flat(rules)
    assert "version_check.enabled" in rules and "ask whether to keep" in rules


def test_mcp_server_instructions_carry_the_rule_and_the_notice():
    assert _flat(NOTICE) in _flat(MCP_INSTRUCTIONS)
    assert "ask whether to keep" in MCP_INSTRUCTIONS
    assert "version_check.enabled" in MCP_INSTRUCTIONS


def test_cli_copy_is_identical():
    path = ROOT / "cli/src/boxmunge_cli/server_setup/version_check_notice.py"
    spec = importlib.util.spec_from_file_location("cli_notice", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.NOTICE == NOTICE


def test_notice_states_the_documented_facts():
    ops = _flat((ROOT / "docs/on-server/OPERATIONS.md").read_text())
    section = ops.split("### What boxmunge sends home")[1]
    for fact in ("every 6 hours", "/v1/check?v=<installed version>", "boxmunge/<installed version>",
                 "IPv4 /24, IPv6 /48", "90 days", "not anonymous", "hostname, machine ID or project names",
                 "upgrade --target X.Y.Z"):
        assert fact in _flat(NOTICE) and fact in section, fact
    assert "version_check.enabled: false" in NOTICE


def test_install_records_the_choice():
    script = (ROOT / "bootstrap/init-host.sh").read_text()
    assert "--no-version-check) VERSION_CHECK=false" in script
    assert "version_check:\n  enabled: ${VERSION_CHECK}" in script
