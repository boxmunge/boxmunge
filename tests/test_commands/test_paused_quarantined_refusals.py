# SPDX-License-Identifier: Apache-2.0
"""A refusal names a command the project's state accepts. `recover` and
`pause` of a project that is paused and CVE-quarantined (or paused during a
userns migration) must not send the operator to `resume`, which that state
refuses too: they name what lifecycle.paused_refusal names for it (shown to
run in test_resume_no_start), or the migration's own way out."""
from __future__ import annotations

import pytest
import yaml

from boxmunge.commands.pause_cmd import run_pause
from boxmunge.commands.recover_cmd import run_recover
from boxmunge.commands.resume_cmd import run_resume
from boxmunge.lifecycle import is_blocked, paused_refusal
from boxmunge.pause import mark_pause_complete, write_paused_state
from boxmunge.userns.marker import SHIM, set_marker
from tests.test_commands.cve_helpers import seed_quarantine

P = "myapp"


@pytest.fixture
def paused(paths):
    pdir = paths.project_dir(P)
    pdir.mkdir(parents=True)
    (pdir / "manifest.yml").write_text(yaml.safe_dump({"project": P}))
    write_paused_state(P, paths, reason="maintenance")
    mark_pause_complete(P, paths)
    return paths


@pytest.mark.parametrize("refused_by", [run_recover, run_pause], ids=["recover", "pause"])
def test_paused_and_quarantined_names_the_way_that_state_takes(
        paused, capsys, refused_by) -> None:
    seed_quarantine(paused, P)
    assert refused_by(P, paused, yes=True) == 1
    err = capsys.readouterr().err
    assert paused_refusal(P, is_blocked(P, paused)) in err
    assert run_resume(P, paused, yes=True) == 1   # what they used to name
    assert "CVE-quarantined" in capsys.readouterr().err


@pytest.mark.parametrize("refused_by", [run_recover, run_pause], ids=["recover", "pause"])
def test_a_paused_project_during_a_migration_names_the_migration(
        paused, capsys, refused_by) -> None:
    set_marker(paused, "userns-finish")
    assert refused_by(P, paused, yes=True) == 1
    err = capsys.readouterr().err
    assert f"{SHIM} userns-finish" in err and f"resume {P}`" not in err
    assert f"resume {P}\n" not in err


@pytest.mark.parametrize("refused_by, says", [
    (run_recover, f"paused, not monitor-stopped. Use: boxmunge resume {P}"),
    (run_pause, f"already paused. Run `boxmunge resume {P}`"),
], ids=["recover", "pause"])
def test_only_paused_still_names_resume(paused, capsys, refused_by, says) -> None:
    assert refused_by(P, paused, yes=True) == 1
    assert says in capsys.readouterr().err
