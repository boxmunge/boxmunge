# SPDX-License-Identifier: Apache-2.0
"""`secrets set <scope> KEY` (no '=') takes the value from stdin, so it is in
no process's argv on either end (T8). A terminal gets a no-echo prompt; any
other stdin is read whole, one trailing newline dropped. No data at all is
refused: an empty value must be sent as an empty line, never inferred."""
import io

import pytest

from boxmunge.commands.secrets_cmd import run_secrets
from boxmunge.secrets import SecretsFile, get_key


def _stdin(monkeypatch, text: str) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(text))


def test_the_value_is_read_from_stdin(paths, monkeypatch) -> None:
    _stdin(monkeypatch, "p@ss word; $(x) # y\n")
    assert run_secrets(["set", "myapp", "API_KEY"], paths) == 0
    assert get_key(SecretsFile.project(paths, "myapp"), "API_KEY") == "p@ss word; $(x) # y"


def test_an_empty_line_sets_an_empty_value(paths, monkeypatch) -> None:
    _stdin(monkeypatch, "\n")
    assert run_secrets(["set", "--host", "EMPTY"], paths) == 0
    assert get_key(SecretsFile.host(paths), "EMPTY") == ""


def test_no_data_on_stdin_is_refused_and_nothing_is_written(paths, monkeypatch, capsys) -> None:
    _stdin(monkeypatch, "")
    assert run_secrets(["set", "myapp", "API_KEY"], paths) == 1
    assert "no value for API_KEY on stdin" in capsys.readouterr().err
    assert not paths.project_secrets("myapp").exists()


def test_a_second_line_is_refused_not_dropped(paths, monkeypatch, capsys) -> None:
    _stdin(monkeypatch, "first\nADMIN=1\n")
    assert run_secrets(["set", "myapp", "API_KEY"], paths) == 1
    assert "ERROR:" in capsys.readouterr().err
    assert not paths.project_secrets("myapp").exists()


def test_a_terminal_is_prompted_without_echo(paths, monkeypatch) -> None:
    class _Tty(io.StringIO):
        def isatty(self) -> bool:
            return True
    monkeypatch.setattr("sys.stdin", _Tty(""))
    asked = []
    monkeypatch.setattr("getpass.getpass", lambda prompt: asked.append(prompt) or "typed")
    assert run_secrets(["set", "myapp", "API_KEY"], paths) == 0
    assert asked == ["Value for API_KEY: "]
    assert get_key(SecretsFile.project(paths, "myapp"), "API_KEY") == "typed"


@pytest.mark.parametrize("key", ["BAD KEY", "1X"])
def test_a_bad_key_is_refused_before_stdin_is_read(paths, monkeypatch, key) -> None:
    stdin = io.StringIO("value\n")
    monkeypatch.setattr("sys.stdin", stdin)
    assert run_secrets(["set", "myapp", key], paths) == 1
    assert stdin.tell() == 0
