# SPDX-License-Identifier: Apache-2.0
"""A remedy that says "deploy it again" names a command prod-deploy accepts
from that state. A bundle project's bare `prod-deploy <p>` is refused when
its inbox is empty (deploy_no_bundle), so those remedies name
`--redeploy`, or `--ref <installed commit>` for a git project."""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import pytest

from boxmunge import cli
from boxmunge.paths import BoxPaths
from boxmunge.project_registry import add_project
from boxmunge.redeploy_hint import redeploy_command, redeploy_either
from boxmunge.state import read_state, write_state
from tests.bundle_helpers import place_bundle
from tests.txn_helpers import docker_off

SRC = Path(__file__).resolve().parents[1] / "src" / "boxmunge"
DOCS = Path(__file__).resolve().parents[1] / "docs" / "on-server"
# `prod-deploy {project}`, `prod-deploy <project>` or `prod-deploy <p>`
# with no option after it.
BARE = re.compile(r"prod-deploy (\{[^{}]+\}|<project>|<p>)(?!\s*--)")
# Files whose bare ones are accepted where they are printed: command
# listings (help, usage, the shell's menu, the upload walk-through), a git
# project's (no inbox), and diff's (a bundle is waiting).
ACCEPTED = {
    "commands/help.py": "the command listing",
    "commands/usage.py": "the usage text",
    "shell.py": "the deploy shell's menu",
    "commands/bundle_cmd.py": "the upload walk-through: after the scp",
    "commands/add_git_project_cmd.py": "a git project: no inbox",
    "commands/diff_cmd.py": "printed after comparing the bundle waiting in the inbox",
    "redeploy_hint.py": "a git project never deployed: its ref is what there is",
}
# Anywhere else a bare one must name the redeploy in the same string (the
# message then names both, an upload's deploy and the installed release's),
# or say there that it follows an upload.
BESIDE = ("redeploy_command(", "redeploy_either(", "--redeploy", "pload")


def _docstrings(tree: ast.AST) -> set[int]:
    ids = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if isinstance(body, list) and body and isinstance(body[0], ast.Expr) \
                and isinstance(body[0].value, ast.Constant):
            ids.add(id(body[0].value))
    return ids


def _strings(path: Path) -> list[tuple[int, str]]:
    """(line, text) of every string literal but docstrings. Adjacent
    literals are one string (the parser joins them, so an f-string split
    over lines is whole); an f-string's fields read as `{expression}`."""
    tree = ast.parse(path.read_text())
    skip = _docstrings(tree)
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            found.append((node.lineno, "".join(
                v.value if isinstance(v, ast.Constant) else "{" + ast.unparse(v.value) + "}"
                for v in node.values)))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) \
                and id(node) not in skip:
            found.append((node.lineno, node.value))
    return found


def _bare_without_the_redeploy(path: Path) -> list[str]:
    return [f"{path.relative_to(SRC)}:{line}: {text.strip()[:100]}"
            for line, text in _strings(path)
            if BARE.search(text) and not any(b in text for b in BESIDE)]


def test_no_remedy_names_a_bare_prod_deploy_where_it_is_refused() -> None:
    found = [hit for p in SRC.rglob("*.py") if str(p.relative_to(SRC)) not in ACCEPTED
             for hit in _bare_without_the_redeploy(p)]
    assert found == []


def test_the_operations_guide_names_the_redeploy_for_a_missing_image() -> None:
    text = (DOCS / "OPERATIONS.md").read_text()
    for anchor in ("which is why Compose left it):", "is missing ... run "):
        after = text[text.index(anchor):][:200]
        assert "--redeploy" in after, anchor


def test_the_pattern_catches_a_bare_remedy(tmp_path) -> None:
    assert BARE.search("the deployed image: prod-deploy {project_name} (or stage")
    assert BARE.search("until `prod-deploy <project>`)")
    assert not BARE.search("prod-deploy {project} --redeploy")
    split = tmp_path / "split.py"
    split.write_text('def f(p):\n    return (f"run `prod-"\n            f"deploy {p}` now")\n')
    beside = tmp_path / "beside.py"
    beside.write_text('A = "prod-deploy <p>"\nB = "use --redeploy"\n')
    assert _bare_without_the_redeploy_in(split) and _bare_without_the_redeploy_in(beside)


def _bare_without_the_redeploy_in(path: Path) -> list[str]:
    return [text for _line, text in _strings(path)
            if BARE.search(text) and not any(b in text for b in BESIDE)]


def _deployed_bundle(paths: BoxPaths) -> None:
    add_project("myapp", paths)
    place_bundle(paths, timestamp="2026-10-16T090000000000")
    with docker_off():
        assert _main(["prod-deploy", "myapp"]) == 0


def _main(argv: list[str]) -> int:
    old = sys.argv
    sys.argv = ["boxmunge", *argv]
    try:
        with pytest.raises(SystemExit) as exc:
            cli.main()
    finally:
        sys.argv = old
    return exc.value.code


def test_the_bundle_command_is_accepted_with_an_empty_inbox(paths, monkeypatch) -> None:
    monkeypatch.setattr(BoxPaths.__init__, "__defaults__", (paths.root,))
    _deployed_bundle(paths)
    command = redeploy_command(paths, "myapp")
    assert command == "prod-deploy myapp --redeploy"
    with docker_off():
        assert _main(command.split()) == 0
    assert read_state(paths.project_deploy_state("myapp"))["current_ref"].startswith("myapp-")


def test_a_git_project_names_its_installed_commit(paths) -> None:
    (paths.project_dir("gitapp") / "repo").mkdir(parents=True)
    assert redeploy_command(paths, "gitapp") == "prod-deploy gitapp"
    write_state(paths.project_deploy_state("gitapp"), {"current_ref": "a" * 40})
    assert redeploy_command(paths, "gitapp") == f"prod-deploy gitapp --ref {'a' * 40}"


def test_without_paths_both_forms_are_named() -> None:
    text = redeploy_either("myapp")
    assert "prod-deploy myapp --redeploy" in text and "--ref" in text


def test_health_names_each_awaiting_projects_own_deploy(paths) -> None:
    """A git project has no inbox and refuses --redeploy: its line names its
    commit and its ref, a bundle project's the redeploy and an upload."""
    from boxmunge.health_checks.projects import check_lifecycle_blocked
    from boxmunge.pause import mark_awaiting_deploy, mark_pause_complete, write_paused_state
    (paths.project_dir("gitapp") / "repo").mkdir(parents=True)
    write_state(paths.project_deploy_state("gitapp"), {"current_ref": "a" * 40})
    paths.project_dir("shop").mkdir(parents=True)
    for name in ("gitapp", "shop"):
        (paths.project_dir(name) / "manifest.yml").write_text(f"project: {name}\n")
        write_paused_state(name, paths)
        mark_pause_complete(name, paths)
        mark_awaiting_deploy(name, paths)
    detail = check_lifecycle_blocked(paths).detail
    assert "gitapp (`prod-deploy gitapp --ref " + "a" * 40 + "`" in detail
    assert "prod-deploy gitapp --redeploy" not in detail and "gitapp` after an upload" not in detail
    assert "shop (`prod-deploy shop --redeploy`, or `prod-deploy shop` after an upload)" in detail
    from boxmunge.lifecycle import is_blocked
    for name, ways in (("gitapp", f"`prod-deploy gitapp --ref {'a' * 40}`, or `prod-deploy "
                                  f"gitapp` for the newest commit on its ref"),
                       ("shop", "`prod-deploy shop --redeploy`, or `prod-deploy shop` after "
                                "an upload")):
        block = is_blocked(name, paths)
        assert ways in block.refuse_message and ways in block.skip_message
