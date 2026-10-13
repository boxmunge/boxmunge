# SPDX-License-Identifier: Apache-2.0
"""secrets / rollback / validate / remote, through the real entry point."""

import io
import shlex
from pathlib import Path

import pytest

from boxmunge_cli.cli import main
from boxmunge_cli.init_cmd import run_init


def run_cli(argv: list[str]) -> int:
    with pytest.raises(SystemExit) as exc:
        main(argv)
    return exc.value.code


@pytest.fixture
def project(tmp_path: Path, monkeypatch, fake_remote) -> Path:
    root = tmp_path / "myapp"
    assert run_init(root, server="box.example.com", host="myapp.example.com") == 0
    monkeypatch.chdir(root)
    return root


def _server_argv(fake_remote) -> list[list[str]]:
    """Each ssh call's remote command, parsed the way the server's shell does."""
    return [shlex.split(argv[-1]) for argv in fake_remote.calls("ssh")
            if argv[-1] != "handshake"]


def test_secrets_set_reads_the_value_from_stdin(project, fake_remote, monkeypatch) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("p@ss word; $(x)\n"))
    assert run_cli(["secrets", "set", "API_KEY"]) == 0
    assert _server_argv(fake_remote) == [["secrets", "set", "myapp", "API_KEY=p@ss word; $(x)"]]


def test_secrets_list_get_unset(project, fake_remote) -> None:
    assert run_cli(["secrets", "list"]) == 0
    assert run_cli(["secrets", "get", "API_KEY"]) == 0
    assert run_cli(["secrets", "unset", "API_KEY"]) == 0
    assert _server_argv(fake_remote) == [["secrets", "list", "myapp"],
                                         ["secrets", "get", "myapp", "API_KEY"],
                                         ["secrets", "unset", "myapp", "API_KEY"]]


@pytest.mark.parametrize("argv", [["secrets", "get"], ["secrets", "set", "bad key"],
                                  ["secrets", "get", "A=1"], ["secrets", "list", "A"],
                                  ["secrets", "rotate"]])
def test_bad_secrets_usage(project, fake_remote, argv) -> None:
    assert run_cli(argv) == 2
    assert fake_remote.calls() == []


def test_rollback_and_validate(project, fake_remote) -> None:
    assert run_cli(["rollback", "--yes"]) == 0
    assert run_cli(["validate", "--json"]) == 0
    assert _server_argv(fake_remote) == [["rollback", "myapp", "--yes"],
                                         ["validate", "myapp", "--json"]]


def test_remote_passthrough_keeps_arguments_intact(project, fake_remote) -> None:
    assert run_cli(["remote", "logs", "myapp", "--tail", "5"]) == 0
    assert run_cli(["remote", "--", "inbox", "a b"]) == 0
    assert _server_argv(fake_remote) == [["logs", "myapp", "--tail", "5"],
                                         ["inbox", "a b"]]


def test_remote_needs_a_command(project, fake_remote) -> None:
    assert run_cli(["remote"]) == 2
    assert fake_remote.calls() == []
