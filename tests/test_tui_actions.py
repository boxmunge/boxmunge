# SPDX-License-Identifier: Apache-2.0
"""The TUI shows why an action failed, and offers a redeploy when a deploy
had no new bundle to deploy."""
from __future__ import annotations

import pytest

from boxmunge.commands.deploy import run_deploy
from boxmunge.project_registry import add_project
from boxmunge.tui.actions import run_action
from tests.bundle_helpers import place_bundle
from tests.txn_helpers import docker_off


@pytest.fixture
def deployed(paths):
    add_project("myapp", paths)
    place_bundle(paths, timestamp="2026-10-16T090000000000")
    with docker_off():
        assert run_deploy("myapp", paths) == 0
    return paths


def test_a_deploy_with_no_new_bundle_shows_the_refusal_and_offers_a_redeploy(deployed) -> None:
    with docker_off():
        outcome = run_action("deploy", "myapp", deployed)
    assert not outcome.ok and outcome.offer_redeploy
    assert "No new bundle for 'myapp'" in outcome.message
    assert "Press D to redeploy" in outcome.message


def test_the_offered_redeploy_runs(deployed) -> None:
    with docker_off():
        outcome = run_action("redeploy", "myapp", deployed)
    assert outcome.ok and outcome.message == "redeploy completed for myapp"


def test_another_failure_shows_its_error_without_the_offer(paths) -> None:
    outcome = run_action("deploy", "ghost", paths)
    assert not outcome.ok and not outcome.offer_redeploy
    assert "not registered" in outcome.message
