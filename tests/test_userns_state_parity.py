"""The upgrade shim reads the userns journal on its own (userns.sh,
userns_state) to decide whether an upgrade may run: it must read every
phase the way journal.state() does, and its refusal must name a command
that state accepts."""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

from boxmunge.userns.journal import (
    COMMIT_STARTED, FORWARD, FORWARD_PHASES, ROLLBACK, ROLLBACK_PHASES, Journal, State,
    save_journal, state,
)
from tests.test_userns_state import _GATES

REPO = Path(__file__).resolve().parents[1]
USERNS_SH = REPO / "scripts" / "boxmunge-upgrade.d" / "userns.sh"
S = 1048576
# Stand-ins for what userns.sh calls from the rest of the shim.
_STUBS = ('refuse_symlink() { :; }; die() { echo "DIE: $*" >&2; exit 1; }; '
          'log() { echo "LOG: $*"; }; bm_log() { :; }; ')
# The states in which an upgrade may run: no data part-shifted, no store part-deleted.
UPGRADE_ALLOWED = {State.NONE, State.APPLIED, State.COMMITTED, State.ROLLED_BACK}

_COMMIT = {COMMIT_STARTED: "100"}
JOURNALS = (
    [None]
    + [Journal(FORWARD, phase, S) for phase in FORWARD_PHASES]
    + [Journal(FORWARD, "applied", S, items=_COMMIT),
       Journal(FORWARD, "committed", S, items=_COMMIT),  # what a finished commit leaves
       Journal(FORWARD, "committed", S, fresh_install=True)]
    + [Journal(ROLLBACK, phase, S) for phase in ROLLBACK_PHASES]
)


def _id(j: Journal | None) -> str:
    return "none" if j is None else f"{j.direction}-{j.phase}" + (
        "-commit-began" if COMMIT_STARTED in j.items else "") + (
        "-fresh" if j.fresh_install else "")


def _shim(paths, call: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "UPGRADE_ROOT_DIR": str(paths.upgrade_root),
           "USERNS_SH": str(USERNS_SH), "BOXMUNGE_ROOT": "/opt/boxmunge"}
    return subprocess.run(["bash", "-c", f'{_STUBS}source "$USERNS_SH"; {call}'],
                          capture_output=True, text=True, timeout=30, env=env)


def _as_state(shim_out: str) -> State:
    if not shim_out:
        return State.NONE
    direction, phase = shim_out.split(" ")
    if direction == ROLLBACK:
        return State.ROLLED_BACK if phase == "rolled-back" else State.ROLLING_BACK
    return {"commit": State.COMMITTING, "applied": State.APPLIED,
            "committed": State.COMMITTED}.get(phase, State.MIGRATING)


@pytest.fixture
def written(paths, request):
    """The journal as Python writes it, or none."""
    if request.param is not None:
        save_journal(paths, request.param)
    return request.param


def test_every_state_is_fed_to_both() -> None:
    assert {state(j) for j in JOURNALS} == set(State)


@pytest.mark.parametrize("written", JOURNALS, ids=_id, indirect=True)
def test_shim_and_python_agree_on_every_phase(paths, written) -> None:
    run = _shim(paths, "userns_state")
    assert run.returncode == 0, run.stderr
    out = run.stdout.strip()
    assert _as_state(out) is state(written), out
    if written is not None:  # the phase as journalled, but for a commit that began
        shown = "commit" if state(written) is State.COMMITTING else written.phase
        assert out == f"{written.direction} {shown}"


@pytest.mark.parametrize("written", JOURNALS, ids=_id, indirect=True)
def test_the_shim_upgrades_only_where_python_says_nothing_is_part_way(paths, written) -> None:
    run = _shim(paths, "userns_refuse_mid_migration 9.9.9 check")
    at = state(written)
    assert (run.returncode == 0) is (at in UPGRADE_ALLOWED), run.stderr
    if at not in UPGRADE_ALLOWED:
        named = set(re.findall(r"userns-(?:migrate|rollback|commit)", run.stderr))
        assert named and all(at in _GATES[cmd][1] for cmd in named), run.stderr
