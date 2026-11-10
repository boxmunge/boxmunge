"""Commands never do something other than what was asked (audits D-03,
D-04, D-17).

- ``<command> --help`` / ``-h`` prints usage and exits 0 without acting.
- An unknown flag is a usage error (exit 2, ERROR + usage on stderr), never
  ignored and never a reason to run the default action.
- ``--dry-run`` on a command that does not implement it is rejected.
"""

import importlib
import pkgutil
import sys

import pytest

import boxmunge.commands
from boxmunge import cli
from boxmunge.paths import BoxPaths

# Minimal valid leading arguments for each command, so the bogus flag is
# appended where the command would otherwise accept it.
BASE_ARGS: dict[str, list[str]] = {
    "add-git-project": ["myapp", "https://example.com/r.git"],
    "backup": ["myapp"],
    "bundle": ["./myapp"],
    "check": ["myapp"],
    "data": ["adopt", "myapp", "db:/data", "pgdata"],
    "diff": ["myapp"],
    "logs": ["myapp"],
    "pause": ["myapp"],
    "project-add": ["myapp"],
    "project-delete": ["myapp"],
    "project-forget": ["myapp"],
    "promote": ["myapp"],
    "prod-deploy": ["myapp"],
    "recover": ["myapp"],
    "restore": ["myapp"],
    "resume": ["myapp"],
    "rollback": ["myapp"],
    "secrets": ["list", "myapp"],
    "stage": ["myapp"],
    "stash": ["list"],
    "test-restore": ["myapp"],
    "unstage": ["myapp"],
    "validate": ["myapp"],
    "userns": ["check"],
    "_discover-update": ["--json"],
}

# Subcommand forms that need their own coverage.
EXTRA_FORMS: list[list[str]] = [
    ["inbox", "clean"],
    ["data", "chown", "myapp", "app", "10001:10001"],
    ["secrets", "set", "myapp", "KEY=value"],
    ["secrets", "set", "--host", "KEY=value"],
    ["secrets", "get", "myapp", "KEY"],
    ["secrets", "unset", "myapp", "KEY"],
    ["security", "scan"],
    ["security", "scan", "myapp"],
    ["security", "resume", "myapp"],
    ["security", "suppress", "CVE-2024-0001", "--project", "myapp",
     "--until", "2099-01-01", "--reason", "not reachable"],
    ["security", "unsuppress", "CVE-2024-0001", "--project", "myapp"],
    ["stash", "create"],
    ["stash", "restore", "--latest"],
    ["logs", "--host"],
    ["logs", "--boxmunge"],
    ["help", "status"],
    ["agent-help", "rules"],
]


class _Fired(Exception):
    pass


def _run_functions() -> list[tuple[object, str]]:
    """Every (module, name) of a run_* callable in boxmunge.commands."""
    targets = []
    for info in pkgutil.iter_modules(boxmunge.commands.__path__):
        module = importlib.import_module(f"boxmunge.commands.{info.name}")
        for attr in dir(module):
            if attr.startswith("run_") and callable(getattr(module, attr)):
                targets.append((module, attr))
    return targets


_RUN_FUNCTIONS = _run_functions()


@pytest.fixture
def sandbox(paths: BoxPaths, monkeypatch) -> list[str]:
    """Point default BoxPaths at a temp root and make every run_* raise.

    Returns the list that records which run_* functions were attempted.
    """
    monkeypatch.setattr(BoxPaths.__init__, "__defaults__", (paths.root,))
    fired: list[str] = []
    for module, attr in _RUN_FUNCTIONS:
        def _boom(*a, _name=f"{module.__name__}.{attr}", **kw):
            fired.append(_name)
            raise _Fired(_name)
        monkeypatch.setattr(module, attr, _boom)
    return fired


def _main(argv: list[str], monkeypatch) -> int:
    monkeypatch.setattr(sys, "argv", ["boxmunge", *argv])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    return exc.value.code


@pytest.mark.parametrize("flag", ["--help", "-h"])
@pytest.mark.parametrize("name", sorted(cli.COMMANDS))
def test_help_flag_prints_usage_and_never_acts(
    name: str, flag: str, sandbox, monkeypatch, capsys,
) -> None:
    called: list[str] = []
    for key in list(cli.COMMANDS):
        monkeypatch.setitem(
            cli.COMMANDS, key, lambda args, _k=key: called.append(_k),
        )
    code = _main([name, *BASE_ARGS.get(name, []), flag], monkeypatch)
    assert code == 0
    assert f"boxmunge {name}" in capsys.readouterr().out
    assert called == [], f"{name} {flag} reached the handler"
    assert sandbox == []


@pytest.mark.parametrize("name", sorted(cli.COMMANDS))
def test_unknown_flag_exits_2_without_acting(
    name: str, sandbox, monkeypatch, capsys,
) -> None:
    code = _main([name, *BASE_ARGS.get(name, []), "--bogus-flag"], monkeypatch)
    assert code == 2
    assert "ERROR:" in capsys.readouterr().err
    assert sandbox == [], f"{name} ran {sandbox} despite an unknown flag"


@pytest.mark.parametrize("form", EXTRA_FORMS, ids=" ".join)
def test_unknown_flag_on_subcommand_forms_exits_2(
    form: list[str], sandbox, monkeypatch, capsys,
) -> None:
    code = _main([*form, "--bogus-flag"], monkeypatch)
    assert code == 2
    assert "ERROR:" in capsys.readouterr().err
    assert sandbox == []


@pytest.mark.parametrize("name", sorted(cli.COMMANDS))
def test_unknown_flag_before_arguments_exits_2(
    name: str, sandbox, monkeypatch, capsys,
) -> None:
    code = _main([name, "--bogus-flag", *BASE_ARGS.get(name, [])], monkeypatch)
    assert code == 2
    assert sandbox == []


def test_project_delete_rejects_dry_run_and_deletes_nothing(
    paths: BoxPaths, monkeypatch, capsys,
) -> None:
    """Audit D-03: `project-delete foo --dry-run --yes` deleted the project."""
    monkeypatch.setattr(BoxPaths.__init__, "__defaults__", (paths.root,))
    project_dir = paths.project_dir("foo")
    project_dir.mkdir(parents=True)
    (project_dir / "manifest.yml").write_text("project: foo\n")

    code = _main(["project-delete", "foo", "--dry-run", "--yes"], monkeypatch)

    assert code == 2
    assert "--dry-run" in capsys.readouterr().err
    assert (project_dir / "manifest.yml").exists()


@pytest.mark.parametrize("typo", ["--raed-only", "--read_only", "--readonly",
                                  "read-only", "--help-me"])
def test_check_all_typo_never_runs_the_mutator(
    typo: str, sandbox, monkeypatch,
) -> None:
    """Audit D-04: any argument other than --read-only must not run check-all."""
    code = _main(["check-all", typo], monkeypatch)
    assert code == 2
    assert sandbox == []


def test_check_all_read_only_reaches_read_only_mode(
    paths: BoxPaths, monkeypatch,
) -> None:
    from boxmunge.commands import check as check_mod

    monkeypatch.setattr(BoxPaths.__init__, "__defaults__", (paths.root,))
    seen: list[bool] = []
    monkeypatch.setattr(
        check_mod, "run_check_all",
        lambda paths, *, read_only: seen.append(read_only) or 0,
    )
    assert _main(["check-all", "--read-only"], monkeypatch) == 0
    assert seen == [True]


@pytest.mark.parametrize("argv", [
    ["log", "--tail", "abc"],
    ["log", "--since", "yesterday"],
    ["log", "--project"],
    ["logs", "myapp", "--tail", "abc"],
    ["unstage"],
    ["unstage", "--dry-run"],
    ["diff", "../../etc"],
    ["test-restore", "../../etc"],
    ["backup-sync", "../../etc"],
])
def test_bad_input_is_a_usage_error_not_a_traceback(
    argv: list[str], sandbox, monkeypatch, capsys,
) -> None:
    """Audit D-17: malformed values exit 2 with ERROR, never a traceback."""
    code = _main(argv, monkeypatch)
    assert code == 2
    assert "ERROR:" in capsys.readouterr().err
    assert sandbox == []


# Commands that implement --dry-run. Every other command must reject it.
DRY_RUN_SUPPORTED = {
    "prod-deploy", "stage", "promote", "unstage", "upgrade", "container-update",
}


@pytest.mark.parametrize(
    "name", sorted(set(cli.COMMANDS) - DRY_RUN_SUPPORTED),
)
def test_dry_run_is_rejected_where_unsupported(
    name: str, sandbox, monkeypatch,
) -> None:
    code = _main([name, *BASE_ARGS.get(name, []), "--dry-run"], monkeypatch)
    assert code == 2
    assert sandbox == [], f"{name} ran {sandbox} despite --dry-run"


def test_help_text_lists_exactly_the_dry_run_commands() -> None:
    from boxmunge.commands.help import HELP_TEXT

    options = HELP_TEXT[HELP_TEXT.index("--dry-run  "):HELP_TEXT.index("--yes  ")]
    for name in DRY_RUN_SUPPORTED:
        assert name in options, f"help does not list {name} as supporting --dry-run"
