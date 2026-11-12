# SPDX-License-Identifier: Apache-2.0
"""boxmunge-server upgrade-readiness [--json] (commands.readiness_cmd)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from boxmunge import cli
from boxmunge.commands.readiness_cmd import render_text
from boxmunge.paths import BoxPaths
from boxmunge.readiness_contract import Finding, ProjectReadiness, Readiness, parse
from tests.readiness_helpers import IMAGE, Recorder, add_project, make_box

BLOCK = Finding("box.compose_version", "block", "before", "Compose is too old",
                "as root: apt-get install --only-upgrade docker-compose-plugin")
TODO = Finding("project.compose", "todo", "before", "shop: would be refused",
               "fix compose.yml, then `prod-deploy shop`")


@pytest.fixture
def box(tmp_path: Path, monkeypatch) -> BoxPaths:
    monkeypatch.setattr("boxmunge.docker_run.subprocess.run", Recorder())
    paths = make_box(tmp_path / "bm")
    monkeypatch.setattr(BoxPaths.__init__, "__defaults__", (paths.root,))
    return paths


def _main(argv: list[str], monkeypatch) -> int:
    monkeypatch.setattr(sys, "argv", ["boxmunge", "upgrade-readiness", *argv])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    return exc.value.code


def test_exit_codes_pass_0_blocked_1_unknown_flag_2(box, monkeypatch, capsys) -> None:
    add_project(box, "alpha")
    assert _main([], monkeypatch) == 0
    assert _main(["--json"], monkeypatch) == 0
    box.project_manifest("alpha").write_text("- not\n- a mapping\n")
    assert _main([], monkeypatch) == 1
    assert _main(["--json"], monkeypatch) == 1
    capsys.readouterr()
    for bad in (["--bogus"], ["--dry-run"], ["alpha"]):
        assert _main(bad, monkeypatch) == 2
        assert "ERROR:" in capsys.readouterr().err


def test_json_output_parses_with_contract_parse(box, monkeypatch, capsys) -> None:
    """stdout is one contract-1 object, even when a rule prints on the way
    (the compose validator's WARN for a pull_policy goes to stderr)."""
    add_project(box, "alpha")
    add_project(box, "shop", compose=f"services:\n  web:\n    image: {IMAGE}\n"
                                     f"    pull_policy: always\n")
    assert _main(["--json"], monkeypatch) == 0
    out, err = capsys.readouterr()
    readiness = parse(json.loads(out))
    assert out.count("\n") == 1
    assert [p.name for p in readiness.projects] == ["alpha", "shop"]
    assert [f.id for f in readiness.projects[1].findings] == ["project.validate"]
    assert "WARN" in err


def test_text_lists_box_then_projects_with_remedies() -> None:
    r = Readiness("0.12.0", "0.11.8", (BLOCK,), (
        ProjectReadiness("alpha", ()), ProjectReadiness("shop", (TODO,))))
    text = render_text(r)
    assert text.splitlines()[0] == ("Upgrade readiness for boxmunge 0.12.0 (this box "
                                    "records 0.11.8): BLOCKED")
    box_at, projects_at = text.index("Box:"), text.index("Projects:")
    assert box_at < text.index("BLOCK (before the upgrade) box.compose_version") < projects_at
    assert text.index("fix: as root: apt-get") < projects_at
    assert "  alpha: pass, nothing to do" in text
    shop = text[text.index("  shop: pass"):]
    assert "TO DO (before the upgrade) project.compose: shop: would be refused" in shop
    assert "fix: fix compose.yml, then `prod-deploy shop`" in shop


def test_text_for_a_ready_box() -> None:
    text = render_text(Readiness("0.12.0", "0.11.8", (), ()))
    assert text.endswith("Box:\n  ready\n\nProjects:\n  none")
    assert ": PASS" in text.splitlines()[0]


def test_json_even_when_a_rule_fails(box, monkeypatch, capsys) -> None:
    """The shim reads stdout: a rule that fails is a block in the object,
    never a traceback in place of it."""
    add_project(box, "alpha")

    def broken(name, paths):
        raise TypeError("'int' object is not iterable")
    monkeypatch.setattr("boxmunge.readiness.gather_validation", broken)
    assert _main(["--json"], monkeypatch) == 1
    readiness = parse(json.loads(capsys.readouterr().out))
    [finding] = readiness.projects[0].findings
    assert finding.id == "project.unreadable" and "TypeError" in finding.message
