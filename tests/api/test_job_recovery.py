# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import pytest

from boxmunge.api.job_recovery import (
    Recovery, advice_text, classify, lost_message, recovery_advice, retry_command,
)
from boxmunge.api.worker_identity import WorkerIdentity
from boxmunge.release_txn import load_txn, options_text
from tests.readiness_helpers import add_project, make_box, open_install

WORKER = {"boot_id": "b", "pid": 1, "start_time": 2}


def _rec(state, worker=None):
    return {"id": "J1", "action": "promote", "state": state, "worker": worker}


@pytest.mark.parametrize("state,worker,alive,want", [
    ("queued", None, True, Recovery.START),
    ("running", WORKER, True, Recovery.LEAVE),
    ("running", WORKER, False, Recovery.LOST),
    ("succeeded", WORKER, True, Recovery.COMPLETE_FINISH),
    ("failed", WORKER, False, Recovery.COMPLETE_FINISH),
])
def test_classify_follows_the_recovery_table(state, worker, alive, want):
    seen = []

    def is_alive(identity):
        seen.append(identity)
        return alive
    assert classify(_rec(state, worker), alive=is_alive) is want
    assert seen == ([WorkerIdentity("b", 1, 2)] if state == "running" else [])


@pytest.fixture
def paths(tmp_path):
    p = make_box(tmp_path)
    add_project(p, "myapp")
    return p


@pytest.mark.parametrize("action", ["stage", "promote", "backup", "recover"])
def test_open_install_advice_is_the_txns_own_options(paths, action):
    open_install(paths, "myapp")
    assert options_text("myapp", load_txn(paths, "myapp")) in recovery_advice(paths, action, "myapp")


@pytest.mark.parametrize("action,expected", [
    ("stage", ["boxmunge stage myapp", "boxmunge unstage myapp"]),
    ("pause", ["boxmunge pause myapp"]),
    ("resume", ["boxmunge resume myapp"]),
    ("backup", ["boxmunge backup myapp"]),
    ("restore", ["boxmunge restore myapp"]),
    ("unstage", ["boxmunge unstage myapp"]),
    ("deploy", ["boxmunge status myapp"]),
    ("promote", ["boxmunge status myapp"]),
    ("rollback", ["boxmunge status myapp"]),
    ("recover", ["boxmunge recover myapp"]),
    ("abandon_install", ["boxmunge prod-deploy myapp --abandon"]),
])
def test_advice_per_action_without_an_install(paths, action, expected):
    advice = recovery_advice(paths, action, "myapp")
    for text in expected:
        assert text in advice


def test_lost_message_says_it_was_not_rerun():
    assert "was not run again" in lost_message(_rec("running", WORKER))


def test_advice_text_takes_the_full_action_name(paths):
    assert "boxmunge backup myapp" in advice_text(paths, "project.backup", "myapp")


def test_advice_text_says_when_no_way_out_is_known(paths):
    assert "no way out is known" in advice_text(paths, "project.unknown", "myapp")


def test_retry_command_quotes_the_params():
    record = {"action": "project.backup", "params": '{"project":"myapp"}'}
    assert retry_command(record) == """boxmunge job run project.backup '{"project":"myapp"}'"""
