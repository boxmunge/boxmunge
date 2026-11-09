# SPDX-License-Identifier: Apache-2.0
"""A remedy that says "deploy it again" names a command prod-deploy accepts
from that state. A bundle project's bare `prod-deploy <p>` is refused when
its inbox is empty (deploy_no_bundle), so those remedies name
`--redeploy`, or `--ref <installed commit>` for a git project."""
from __future__ import annotations

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
# A message's `prod-deploy {project}` with no option after it (`<project>`
# forms are command listings: help, usage, the shell's menu).
BARE = re.compile(r"prod-deploy \{[a-z_]+\}(?!\s*--)")
# Files whose bare ones are printed where the bare command is accepted.
ACCEPTED = {
    "redeploy_hint.py": "a git project never deployed: its ref is what there is",
    "commands/check.py": "not deployed yet: a first deploy of an uploaded bundle",
    "commands/validate.py": "not deployed yet: a first deploy of an uploaded bundle",
    "commands/backup_cmd.py": "not deployed yet: a first deploy of an uploaded bundle",
    "commands/add_git_project_cmd.py": "a git project: no inbox",
    "commands/diff_cmd.py": "printed after comparing the bundle waiting in the inbox",
    "commands/deploy_no_bundle.py": "after an upload, or for a git project",
}
# Anywhere else a bare one must sit beside the redeploy: the message then
# names both, an upload's deploy and the installed release's.
BESIDE = ("redeploy_command(", "redeploy_either(", "--redeploy")


def _bare_without_the_redeploy(path: Path) -> list[str]:
    lines = path.read_text().splitlines()
    return [f"{path.relative_to(SRC)}:{i + 1}: {line.strip()}"
            for i, line in enumerate(lines) if BARE.search(line)
            and not any(b in "\n".join(lines[max(i - 2, 0):i + 3]) for b in BESIDE)]


def test_no_remedy_names_a_bare_prod_deploy_where_it_is_refused() -> None:
    found = [hit for p in SRC.rglob("*.py") if str(p.relative_to(SRC)) not in ACCEPTED
             for hit in _bare_without_the_redeploy(p)]
    assert found == []


def test_the_operations_guide_names_the_redeploy_for_a_missing_image() -> None:
    text = (DOCS / "OPERATIONS.md").read_text()
    for anchor in ("which is why Compose left it):", "is missing ... run "):
        after = text[text.index(anchor):][:200]
        assert "--redeploy" in after, anchor


def test_the_pattern_catches_a_bare_remedy() -> None:
    assert BARE.search("the deployed image: prod-deploy {project_name} (or stage")
    assert not BARE.search("prod-deploy {project} --redeploy")


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
