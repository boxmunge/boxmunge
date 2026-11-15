# SPDX-License-Identifier: Apache-2.0
"""A deploy guard refusal (commands/security_regression_guard) on each
route a person working on a project takes: prod-deploy, stage, promote and
rollback stop before anything starts and say what to do from there. The
guard itself is tested in test_security_regression_guard.py; here it
refuses as it does for a release carrying a known-exploited CVE."""
from __future__ import annotations

import pytest

from boxmunge.commands import security_regression_guard as guard
from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.promote_cmd import run_promote
from boxmunge.commands.rollback import run_rollback
from boxmunge.commands.stage_cmd import run_stage
from boxmunge.project_registry import add_project
from boxmunge.staged_release import load_slot
from boxmunge.state import read_state
from tests.bundle_helpers import place_bundle
from tests.stage_helpers import V1, V2, prod_and_stage, staging_docker_off

CVE_LINE = ("CVE-2026-7777 in libc 1 (fixed in 7.0.9), service web (nginx): listed as "
            "actively exploited by CISA KEV")


@pytest.fixture
def refusing(monkeypatch) -> list[bool]:
    """The guard refuses every release; records whether each was staging's."""
    seen: list[bool] = []

    def refuse(paths, target, manifest):
        seen.append(target.staging)
        raise guard.SecurityRegressionRefused(
            [f"This release carries a known-exploited CVE; nothing was started in "
             f"{'staging' if target.staging else 'production'}:", CVE_LINE], guard.FIX_IN_REPO)
    monkeypatch.setattr(guard, "guard_release", refuse)
    return seen


def test_prod_deploy_is_refused_and_nothing_starts(paths, refusing, capsys) -> None:
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1)
    with staging_docker_off() as docker:
        assert run_deploy("myapp", paths) == 1
    err = capsys.readouterr().err
    assert CVE_LINE in err and guard.FIX_IN_REPO in err
    assert refusing == [False]
    docker["up"].assert_not_called()
    assert "current_ref" not in read_state(paths.project_deploy_state("myapp"))


def test_stage_is_refused_and_nothing_starts(paths, refusing, capsys) -> None:
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1)
    with staging_docker_off() as docker:
        assert run_stage("myapp", paths) == 1
    assert CVE_LINE in capsys.readouterr().err
    assert refusing == [True]
    docker["up"].assert_not_called()
    assert load_slot(paths, "myapp") is None


def test_promote_is_refused_and_production_is_unchanged(paths, monkeypatch, capsys) -> None:
    prod_and_stage(paths)
    live = read_state(paths.project_deploy_state("myapp"))["current_ref"]
    seen: list[bool] = []

    def refuse(paths_, target, manifest):
        seen.append(target.staging)
        raise guard.SecurityRegressionRefused([CVE_LINE], guard.FIX_IN_REPO)
    monkeypatch.setattr(guard, "guard_release", refuse)
    with staging_docker_off() as docker:
        assert run_promote("myapp", paths) == 1
        docker["up"].assert_not_called()
    assert CVE_LINE in capsys.readouterr().err and seen == [False]
    assert read_state(paths.project_deploy_state("myapp"))["current_ref"] == live
    assert load_slot(paths, "myapp") is not None  # still staged, for the fix


def test_rollback_is_refused_with_rollbacks_own_exits(paths, monkeypatch, capsys) -> None:
    add_project("myapp", paths)
    for ts, version in ((V1, "v1\n"), (V2, "v2\n")):
        place_bundle(paths, timestamp=ts, files={"VERSION": version})
        with staging_docker_off():
            assert run_deploy("myapp", paths) == 0
    capsys.readouterr()

    def refuse(paths_, target, manifest):
        raise guard.SecurityRegressionRefused(["This release carries a known-exploited CVE; "
                                               "nothing was started in production:", CVE_LINE],
                                              guard.FIX_IN_REPO)
    monkeypatch.setattr(guard, "guard_release", refuse)
    with staging_docker_off() as docker:
        assert run_rollback("myapp", paths, yes=True) == 1
        docker["up"].assert_not_called()
    err = capsys.readouterr().err
    assert "ERROR: The deploy guard refused the previous release:" in err
    assert f"  {CVE_LINE}" in err
    assert ("'rollback myapp --allow-security-regression --reason \"<why>\"' (logged and "
            "alerted)") in err
    assert "upload it and run 'prod-deploy myapp'" in err
    assert "Generating the previous release's configs failed" not in err
    assert "deploy again" not in err  # a deploy's exit, not a rollback's
    assert read_state(paths.project_deploy_state("myapp"))["current_ref"] == f"myapp-{V2}"
