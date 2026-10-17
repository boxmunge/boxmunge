# SPDX-License-Identifier: Apache-2.0
"""deploy.pre_deploy runs on the host without a shell, and the docs say so."""
import re
from pathlib import Path

import pytest

from boxmunge.commands.deploy import run_pre_deploy_hook
from boxmunge.paths import BoxPaths

REPO = Path(__file__).resolve().parents[1]
# Shell syntax the hook would pass to the program as literal arguments.
SHELL_SYNTAX = re.compile(r"&&|\|\||[|;<>`$]")


def _documented_hooks() -> list[tuple[str, str]]:
    sources = [*(REPO / "docs" / "on-server").glob("*.md"), REPO / "README.md",
               *(REPO / "templates").rglob("*"),
               *(REPO / "cli" / "src" / "boxmunge_cli" / "templates").rglob("*")]
    hooks = []
    for path in sources:
        if not path.is_file():
            continue
        for value in re.findall(r"pre_deploy:\s*[\"']?([^\"'\n#]*)", path.read_text()):
            hooks.append((path.relative_to(REPO).as_posix(), value.strip()))
    return hooks


def test_documented_hooks_are_a_command_and_its_arguments() -> None:
    hooks = _documented_hooks()
    assert any(value for _, value in hooks)  # the reference shows a real example
    for where, value in hooks:
        assert not SHELL_SYNTAX.search(value), f"{where}: {value!r} needs a shell"


def test_no_doc_promises_a_migrate_script() -> None:
    for path in [*(REPO / "docs" / "on-server").glob("*.md"), REPO / "README.md"]:
        assert "migrate.sh" not in path.read_text(), path


@pytest.fixture
def project(tmp_path: Path) -> tuple[BoxPaths, Path]:
    paths = BoxPaths(root=tmp_path / "bm")
    project_dir = paths.project_dir("demo")
    (project_dir / "boxmunge-scripts").mkdir(parents=True)
    return paths, project_dir


def test_the_documented_script_form_runs_in_the_project_directory(project) -> None:
    paths, project_dir = project
    script = project_dir / "boxmunge-scripts" / "pre-deploy.sh"
    script.write_text("#!/bin/sh\nset -e\necho one > ran\necho two >> ran\n")
    script.chmod(0o755)
    manifest = {"deploy": {"pre_deploy": "boxmunge-scripts/pre-deploy.sh"}}
    assert run_pre_deploy_hook("demo", paths, manifest) == 0
    assert (project_dir / "ran").read_text() == "one\ntwo\n"


@pytest.mark.parametrize("command,problem", [
    ("no-such-program-anywhere --flag", "not found"),
    ("boxmunge-scripts/not-executable.sh", "not executable"),
])
def test_a_hook_that_cannot_start_is_a_clear_error(project, capsys, command, problem) -> None:
    paths, project_dir = project
    (project_dir / "boxmunge-scripts" / "not-executable.sh").write_text("#!/bin/sh\n")
    assert run_pre_deploy_hook("demo", paths, {"deploy": {"pre_deploy": command}}) == 1
    err = capsys.readouterr().err
    assert "Pre-deploy command cannot run" in err and problem in err
    assert "without a shell" in err
