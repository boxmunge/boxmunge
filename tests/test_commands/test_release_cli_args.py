"""Argument handling for the release commands (review finding on P1).

`rollback myapp --dry-run --yes` performed a real rollback, `unstage
--dry-run` tracebacked. Every release command parses strictly with
commands.argv.parse_args.
"""
from __future__ import annotations

import sys

import pytest

from boxmunge import cli
from boxmunge.paths import BoxPaths


def _main(argv: list[str], monkeypatch) -> int:
    monkeypatch.setattr(sys, "argv", ["boxmunge", *argv])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    return exc.value.code


@pytest.fixture
def no_run(monkeypatch, paths: BoxPaths):
    """Default BoxPaths at a temp root; record any run_* that is reached."""
    from boxmunge.commands import deploy, rollback, stage_cmd, unstage_cmd
    monkeypatch.setattr(BoxPaths.__init__, "__defaults__", (paths.root,))
    called: list[tuple[str, tuple, dict]] = []
    for module, name in [(deploy, "run_deploy"), (stage_cmd, "run_stage"),
                         (rollback, "run_rollback"), (unstage_cmd, "run_unstage")]:
        monkeypatch.setattr(module, name,
                            lambda *a, _n=name, **k: called.append((_n, a, k)) or 0)
    return called


def test_rollback_dry_run_is_refused_and_does_nothing(no_run, monkeypatch, capsys) -> None:
    assert _main(["rollback", "myapp", "--dry-run", "--yes"], monkeypatch) == 2
    assert no_run == []
    assert "--dry-run" in capsys.readouterr().err


def test_unstage_dry_run_is_passed_through(no_run, monkeypatch) -> None:
    assert _main(["unstage", "myapp", "--dry-run"], monkeypatch) == 0
    assert no_run[0][0] == "run_unstage" and no_run[0][2]["dry_run"] is True


@pytest.mark.parametrize("argv", [
    ["prod-deploy", "myapp", "--ref"],
    ["stage", "myapp", "--ref"],
    ["prod-deploy", "myapp", "--ref", "a", "--ref", "b"],
    ["stage", "myapp", "extra"],
    ["prod-deploy", "Bad_Name"],
])
def test_malformed_release_arguments_exit_2(argv, no_run, monkeypatch, capsys) -> None:
    assert _main(argv, monkeypatch) == 2
    assert no_run == []
    assert "Usage:" in capsys.readouterr().err


def test_prod_deploy_options_reach_the_command(no_run, monkeypatch) -> None:
    argv = ["prod-deploy", "myapp", "--ref", "myapp-2026", "--no-snapshot", "--dry-run"]
    assert _main(argv, monkeypatch) == 0
    name, args, kwargs = no_run[0]
    assert (name, args[0]) == ("run_deploy", "myapp")
    assert kwargs == {"ref": "myapp-2026", "no_snapshot": True, "dry_run": True}


def test_stage_options_reach_the_command(no_run, monkeypatch) -> None:
    assert _main(["stage", "myapp", "--ref", "x", "--dry-run"], monkeypatch) == 0
    name, args, kwargs = no_run[0]
    assert (name, args[0]) == ("run_stage", "myapp")
    assert kwargs == {"ref": "x", "dry_run": True}


def test_import_is_not_a_command() -> None:
    """import_cmd was never registered; the dead module is gone."""
    assert "import" not in cli.COMMANDS
    with pytest.raises(ModuleNotFoundError):
        __import__("boxmunge.commands.import_cmd")


def test_prod_deploy_abandon_reaches_run_abandon(no_run, monkeypatch) -> None:
    from boxmunge.commands import install_abandon
    called: list[str] = []
    monkeypatch.setattr(install_abandon, "run_abandon", lambda p, _paths: called.append(p) or 0)
    assert _main(["prod-deploy", "myapp", "--abandon"], monkeypatch) == 0
    assert called == ["myapp"] and no_run == []


@pytest.mark.parametrize("extra", [["--dry-run"], ["--no-snapshot"], ["--ref", "x"]])
def test_prod_deploy_abandon_takes_no_other_options(extra, no_run, monkeypatch, capsys) -> None:
    assert _main(["prod-deploy", "myapp", "--abandon", *extra], monkeypatch) == 2
    assert no_run == []
    assert "--abandon takes no other options" in capsys.readouterr().err
