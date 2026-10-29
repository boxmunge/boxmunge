# SPDX-License-Identifier: Apache-2.0
"""No message tells the user to run a bare `deploy` command: the command is
`prod-deploy` (`deploy` is only the shell's user name)."""
from __future__ import annotations

import re
from pathlib import Path

from boxmunge.commands.help import HELP_TEXT as _HELP  # noqa: F401
from boxmunge.commands.usage import USAGE

SRC = Path(__file__).resolve().parents[1] / "src" / "boxmunge"
# A `deploy <p>` / `deploy {project}` hint, quoted or in prose; not `deploy:deploy`,
# `prod-deploy <p>`, `would deploy {x}` (a verb before a name) or `deploy@host`.
BARE = re.compile(r"""(?<![-\w.@:])(?<!ould )deploy [<{]""")


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
    assert "stage gitapp --ref <ref> --dry-run" in err and "Upload with scp" not in err


def test_the_pattern_catches_the_hints_that_were_fixed():
    for old in ("; deploy {project_name} to decide from it.",
                "change, declare security.user if needed, and deploy {project}: the deploy",
                "Run 'stage {name}' or 'deploy {name}' to start it.",
                'ssh -p 922 deploy@<host> "deploy <project>"'):
        assert BARE.search(old), old
    for fine in ("prod-deploy {project}", "chown -R deploy:deploy {repo}", "deploy@<host>"):
        assert not BARE.search(fine), fine


def test_diff_with_an_unloadable_manifest_reports_it(paths, capsys):
    from boxmunge.commands.diff_cmd import run_diff
    pdir = paths.project_dir("broken")
    pdir.mkdir(parents=True)
    (pdir / "manifest.yml").write_text("{truncated")
    assert run_diff("broken", paths) == 1
    assert "Upload with scp" not in capsys.readouterr().err
