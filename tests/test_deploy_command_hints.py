# SPDX-License-Identifier: Apache-2.0
"""No message tells the user to run a bare `deploy` command: the command is
`prod-deploy` (`deploy` is only the shell's user name)."""
from __future__ import annotations

import re
from pathlib import Path

from boxmunge.commands.help import HELP_TEXT as _HELP  # noqa: F401
from boxmunge.commands.usage import USAGE

SRC = Path(__file__).resolve().parents[1] / "src" / "boxmunge"
# `boxmunge deploy x`, 'deploy <p>' / "deploy {name}" in quotes, `ssh ... "deploy <p>"`.
BARE = re.compile(r"""(boxmunge deploy (?!shell)|['"`]deploy [<{])""")


def test_no_source_string_suggests_a_bare_deploy_command():
    found = [f"{p.relative_to(SRC)}:{i}: {line.strip()}"
             for p in SRC.rglob("*.py")
             for i, line in enumerate(p.read_text().splitlines(), 1) if BARE.search(line)]
    assert found == []


def test_help_and_usage_do_not_either():
    for text in [_HELP, *USAGE.values()]:
        assert not BARE.search(text)


def test_diff_of_a_git_project_says_it_compares_bundles_only(paths, capsys):
    from boxmunge.commands.diff_cmd import run_diff
    pdir = paths.project_dir("gitapp")
    pdir.mkdir(parents=True)
    (pdir / "manifest.yml").write_text(
        "schema_version: 3\nproject: gitapp\nsource: git\nhosts: [a.example.com]\n"
        "services: {web: {port: 80, routes: [{path: /}]}}\n")
    assert run_diff("gitapp", paths) == 1
    err = capsys.readouterr().err
    assert "git project" in err and "compares inbox bundles only" in err
    assert "stage gitapp --ref" in err and "Upload with scp" not in err
