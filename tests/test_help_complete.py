# SPDX-License-Identifier: Apache-2.0
"""`help` names only commands, subcommands, flags and topics that exist, and
lists every command, each in the section that says who may run it.

The dispatch tables are the truth: cli.COMMANDS (what boxmunge-server runs),
shell.ALLOWED_COMMANDS (what the deploy shell lets through) and the upgrade
shim's own subcommands.
"""
from __future__ import annotations

import re
from pathlib import Path

from boxmunge import cli, shell
from boxmunge.commands.bundle_cmd import BUNDLE_HELP
from boxmunge.commands.help import AGENT_HELP_TEXT, AGENT_HELP_TOPICS, HELP_TEXT
from boxmunge.commands.usage import USAGE
from tests.test_command_surface import DRY_RUN_SUPPORTED

REPO = Path(__file__).resolve().parents[1]
SHIM = "boxmunge-upgrade"
OPERATOR_SECTION = "Operator only (as root, not in the deploy shell):"
INTERNAL_PREFIX = "Internal (run by the upgrade shim, not by hand):"
# Registered so that typing it explains it is the root bootstrap script.
NOT_A_COMMAND = {"init-host"}
# The userns migration is run through the shim's userns-* subcommands.
VIA_SHIM = {"userns"}


def _sections() -> dict[str, list[list[str]]]:
    """Section title -> its entries; an entry is its line plus continuation lines."""
    sections: dict[str, list[list[str]]] = {}
    current: list[list[str]] | None = None
    for line in HELP_TEXT.splitlines():
        if line.endswith(":") and not line.startswith(" "):
            current = sections.setdefault(line, [])
        elif not line.strip() or not line.startswith(" "):
            current = None
        elif current is not None:
            if re.match(r"  \S", line) and not line.startswith("  -"):
                current.append([line])
            elif current:
                current[-1].append(line)
    return sections


def _command_entries() -> list[tuple[str, str, list[str]]]:
    """(section, command, entry) for every command line outside Options."""
    return [(title, entry[0].split()[0], entry)
            for title, entries in _sections().items() if not title.startswith("Options")
            for entry in entries]


def _internal() -> set[str]:
    block = HELP_TEXT[HELP_TEXT.index(INTERNAL_PREFIX) + len(INTERNAL_PREFIX):]
    block = block.split("\n\n", 1)[0]
    return {name.strip() for name in block.replace("\n", " ").split(",")}


def _shim_subcommands() -> set[str]:
    text = (REPO / "scripts" / SHIM).read_text()
    case = text[text.rindex('case "${1:-}" in'):]
    return set(re.findall(r"^\s+([a-z][a-z-]*)\)", case, re.MULTILINE))


def _listed() -> set[str]:
    return {cmd for _, cmd, _ in _command_entries() if cmd != SHIM}


def test_every_command_in_help_exists() -> None:
    unknown = _listed() - set(cli.COMMANDS)
    assert not unknown, f"help lists commands boxmunge-server does not have: {unknown}"
    assert _internal() <= set(cli.COMMANDS)


def test_every_shim_command_in_help_exists() -> None:
    named = {entry[0].split()[1] for _, cmd, entry in _command_entries() if cmd == SHIM}
    assert named and named <= _shim_subcommands(), named - _shim_subcommands()


def test_help_lists_every_registered_command() -> None:
    shown = _listed() | _internal() | NOT_A_COMMAND | VIA_SHIM
    missing = set(cli.COMMANDS) - shown
    assert not missing, f"registered commands missing from help: {sorted(missing)}"
    assert "userns-migrate" in HELP_TEXT


def test_operator_section_is_exactly_what_the_deploy_shell_refuses() -> None:
    operator = {cmd for title, cmd, _ in _command_entries()
                if title == OPERATOR_SECTION and cmd != SHIM}
    expected = (set(cli.COMMANDS) - shell.ALLOWED_COMMANDS
                - _internal() - NOT_A_COMMAND - VIA_SHIM)
    assert operator == expected


def test_commands_outside_the_operator_section_run_in_the_deploy_shell() -> None:
    elsewhere = {cmd for title, cmd, _ in _command_entries() if title != OPERATOR_SECTION}
    assert elsewhere <= shell.ALLOWED_COMMANDS, elsewhere - shell.ALLOWED_COMMANDS
    assert not _internal() & shell.ALLOWED_COMMANDS


def test_every_allowed_shell_command_is_in_help() -> None:
    assert shell.ALLOWED_COMMANDS <= _listed()


def test_flags_and_subcommands_in_help_are_in_the_commands_usage() -> None:
    for _, cmd, entry in _command_entries():
        if cmd == SHIM:
            continue
        usage = USAGE[cmd]
        for flag in re.findall(r"--[a-z][a-z-]*", " ".join(entry)):
            assert flag in usage, f"help gives {cmd} {flag}; its usage does not"
        words = entry[0].split()
        if len(words) > 1 and re.fullmatch(r"[a-z][a-z-]*", words[1]):
            assert f"boxmunge {cmd} {words[1]}" in usage, f"help names '{cmd} {words[1]}'"


def test_shell_banner_names_only_allowed_commands() -> None:
    banner = shell._shell_banner()
    names = set(re.findall(r"^  ([a-z][a-z-]*)", banner, re.MULTILINE))
    assert names and names <= shell.ALLOWED_COMMANDS, names - shell.ALLOWED_COMMANDS


def test_agent_help_topics_match_the_topic_table() -> None:
    listed = AGENT_HELP_TEXT.split("Topics (agent-help <topic>):", 1)[1]
    assert set(re.findall(r"^  ([a-z-]+) ", listed, re.MULTILINE)) == set(AGENT_HELP_TOPICS)
    usage_topics = USAGE["agent-help"].split("Topics:", 1)[1].rstrip(".")
    assert {t.strip() for t in usage_topics.split(",")} == set(AGENT_HELP_TOPICS)


def test_agent_help_dry_run_list_matches_the_shell() -> None:
    match = re.search(r"--dry-run works on\s(.*?);", AGENT_HELP_TEXT, re.DOTALL)
    assert match is not None, "agent-help no longer says which commands take --dry-run"
    names = set(re.findall(r"[a-z][a-z-]+", match.group(1))) - {"and"}
    assert names == DRY_RUN_SUPPORTED & shell.ALLOWED_COMMANDS


def test_bundle_help_suggests_only_shell_commands() -> None:
    suggested = set(re.findall(r'deploy@<host> "([a-z][a-z-]*)', BUNDLE_HELP))
    assert suggested and suggested <= shell.ALLOWED_COMMANDS
