"""One reading of the journal's state: a refusal names only commands that
state accepts, proven against each command's own refusal check."""
from __future__ import annotations

import re
from datetime import datetime, timezone

import pytest

from boxmunge.health_checks import userns as health
from boxmunge.userns import commit as cm
from boxmunge.userns import engine as en
from boxmunge.userns import rollback as rb
from boxmunge.userns.journal import (
    COMMIT_STARTED, FORWARD, FORWARD_PHASES, ROLLBACK, ROLLBACK_PHASES, Journal, State,
    finish_hint, save_journal, state,
)
from boxmunge.userns.switch import MigrationError

S = 1048576


def test_a_rerun_after_a_commit_began_does_not_offer_the_rollback() -> None:
    """The old root is partly deleted: userns-rollback refuses this state,
    so the migration's refusal must not send the operator to it."""
    j = Journal(FORWARD, "applied", S, items={"commit-before": "100"})
    with pytest.raises(MigrationError):
        rb._refuse(j)
    with pytest.raises(MigrationError) as e:
        en._refuse_rerun(j)
    assert "userns-rollback" not in str(e.value) and "userns-commit" in str(e.value)


_JOURNALS = {
    State.NONE: None,
    State.MIGRATING: Journal(FORWARD, "started", S),
    State.APPLIED: Journal(FORWARD, "applied", S, applied_at="2026-10-16T00:00:00+00:00"),
    State.COMMITTING: Journal(FORWARD, "applied", S, applied_at="2026-10-16T00:00:00+00:00",
                              items={COMMIT_STARTED: "100"}),
    State.COMMITTED: Journal(FORWARD, "committed", S, fresh_install=True),
    State.ROLLING_BACK: Journal(ROLLBACK, "rb-saved", S),
    State.ROLLED_BACK: Journal(ROLLBACK, "rolled-back", S),
}
# Each command's own refusal check, and the states it runs from.
_GATES = {
    "userns-migrate": (en._refuse_rerun, {State.NONE, State.MIGRATING, State.ROLLED_BACK}),
    "userns-rollback": (rb._refuse, {State.MIGRATING, State.APPLIED, State.ROLLING_BACK}),
    "userns-commit": (cm._refuse, {State.APPLIED, State.COMMITTING}),
}
_COMMAND = re.compile(r"userns-(?:migrate|rollback|commit)")


def test_every_state_is_covered() -> None:
    assert set(_JOURNALS) == set(State)
    assert all(state(j) is s for s, j in _JOURNALS.items())
    for phase in FORWARD_PHASES[:5]:
        assert state(Journal(FORWARD, phase, S)) is State.MIGRATING
    for phase in ROLLBACK_PHASES[:-1]:
        assert state(Journal(ROLLBACK, phase, S)) is State.ROLLING_BACK


@pytest.mark.parametrize("at", list(State), ids=lambda s: s.value)
def test_each_command_runs_from_its_states_and_refuses_the_rest_with_the_hint(at) -> None:
    j = _JOURNALS[at]
    for command, (gate, accepted) in _GATES.items():
        if at in accepted:
            gate(j)
        else:
            with pytest.raises(MigrationError) as e:
                gate(j)
            assert str(e.value).endswith(finish_hint(j)), command


@pytest.mark.parametrize("at", list(State), ids=lambda s: s.value)
def test_a_hint_names_only_commands_its_state_accepts(at, paths, monkeypatch) -> None:
    """The hint is every refusal's and --check's wording; the health
    check words its own. Whatever either names, that command's own check
    lets the journal through."""
    j = _JOURNALS[at]
    monkeypatch.setattr(health, "_is_root", lambda: True)
    if j is not None:
        save_journal(paths, j)
    said = health._journal_check(paths, datetime(2026, 11, 1, tzinfo=timezone.utc))
    for text in (finish_hint(j), finish_hint(j, "sudo x "), said.detail if said else ""):
        for command in _COMMAND.findall(text):
            _GATES[command][0](j)
    assert finish_hint(j, "sudo x ").replace("sudo x ", "") == finish_hint(j)


def test_what_each_state_is_told() -> None:
    told = {at.value: finish_hint(j) for at, j in _JOURNALS.items()}
    assert told == {
        "none": "there is no userns migration",
        "migrating": "a userns migration stopped at started; resume it: userns-migrate, or "
                     "undo it: userns-rollback",
        "applied": f"the userns migration is already applied (offset {S}); soak, then "
                   "userns-commit, or undo it: userns-rollback",
        "committing": "a userns-commit stopped part-way, after it began deleting the old root; "
                      "finish it: userns-commit",
        "committed": f"the userns migration is already committed (offset {S})",
        "rolling back": "a userns rollback stopped at rb-saved; finish it: userns-rollback",
        "rolled back": "the userns migration was already rolled back",
    }
