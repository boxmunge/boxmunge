# SPDX-License-Identifier: Apache-2.0
"""Printed hints name real server commands and the configured connection."""

import re
from pathlib import Path

import pytest

from boxmunge_cli.cli import main
from boxmunge_cli.init_cmd import run_init
from boxmunge_cli.server_setup.command import next_steps


def run_cli(argv: list[str]) -> int:
    with pytest.raises(SystemExit) as exc:
        main(argv)
    return exc.value.code


@pytest.fixture
def project(tmp_path: Path, monkeypatch, fake_remote) -> Path:
    root = tmp_path / "myapp"
    assert run_init(root, server="box.example.com", port=2222,
                    host="myapp.example.com") == 0
    monkeypatch.chdir(root)
    return root


def test_bundle_help_names_server_commands(capsys) -> None:
    assert run_cli(["bundle", "--help"]) == 0
    out = capsys.readouterr().out
    assert "prod-deploy" in out
    assert not re.search(r'"deploy <project>"', out)
    assert "volume | db-dump" not in out
    assert "postgres" in out and "schema_version: 3" in out and "writable:" in out


def test_standalone_bundle_hint_uses_the_config(project: Path, tmp_path: Path,
                                                capsys) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    assert run_cli(["bundle", "--output", str(out_dir)]) == 0
    out = capsys.readouterr().out
    assert "boxmunge prod-deploy" in out and "boxmunge stage" in out
    assert "scp -P 922" not in out


def test_stage_prints_no_upload_hint(project: Path, capsys) -> None:
    assert run_cli(["stage"]) == 0
    captured = capsys.readouterr()
    assert "scp" not in captured.out + captured.err


def test_bundle_without_config_hints_with_placeholders(tmp_path: Path, capsys) -> None:
    root = tmp_path / "myapp"
    assert run_init(root, server="box.example.com", host="myapp.example.com") == 0
    (root / ".boxmunge").unlink()
    assert run_cli(["bundle", str(root), "--output", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "deploy@<server>:" in out and "prod-deploy myapp" in out


@pytest.mark.parametrize("port, flag", [(922, ""), (2222, " --port 2222")])
def test_server_setup_next_steps_include_the_port(port: int, flag: str) -> None:
    text = next_steps("box.example.com", port)
    assert f"boxmunge init --server box.example.com{flag} " in text + " "
    assert f"ssh -p {port} deploy@box.example.com" in text
