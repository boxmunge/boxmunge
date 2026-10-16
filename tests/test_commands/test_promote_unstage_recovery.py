"""Failed promotions and failed unstages leave state that describes reality
(codebase review findings 09 and 17).

09: once a promote has started the staged release's containers, production
runs it whatever fails afterwards. The kept production release then becomes
the previous release (the rollback target), as after any bundle deploy, and
unstage can never put its old files back under the new containers.

17: if the staging containers cannot be removed, unstage keeps the compose
files that reach them and records the incomplete cleanup, so running it
again finishes the job.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from boxmunge.commands.promote_cmd import run_promote
from boxmunge.commands.rollback import find_rollback_target
from boxmunge.commands.stage_cmd import run_stage
from boxmunge.commands.unstage_cmd import run_unstage, staging_exists
from boxmunge.docker import DockerError
from boxmunge.release import has_prestage, mark_prestage_replaced
from boxmunge.state import read_state

from tests.bundle_helpers import place_bundle
from tests.test_commands.test_stage_promote_release import V1, _docker, _prod_v1_staged_v2

NAME = "myapp"
V3 = "2026-10-13T110000000000"


def _version(paths) -> str:
    return (paths.project_dir(NAME) / "VERSION").read_text()


def _failing_promote(paths) -> list[str]:
    """Promote whose final smoke check fails after production was started.
    Returns which release's files production containers were started on."""
    running: list[str] = []

    def up(*args, project_name, **kwargs):
        running.append(_version(paths))
    with _docker(), patch("boxmunge.commands.deploy.compose_up", up), \
            patch("boxmunge.commands.deploy.smoke_ok", return_value=False):
        assert run_promote(NAME, paths) == 1
    return running


def test_promote_failing_after_start_makes_the_production_release_previous(
    paths, capsys,
) -> None:
    _prod_v1_staged_v2(paths)
    assert _failing_promote(paths) == ["v2\n"]
    err = capsys.readouterr().err
    assert "production now runs" in err and f"rollback {NAME}" in err
    assert not has_prestage(paths, NAME)
    assert find_rollback_target(paths, NAME).ref == f"{NAME}-{V1}"


def test_unstage_after_failed_promote_never_reverts_files_under_new_containers(
    paths,
) -> None:
    _prod_v1_staged_v2(paths)
    _failing_promote(paths)
    with _docker():
        assert run_unstage(NAME, paths) == 0
    assert _version(paths) == "v2\n"
    assert not staging_exists(NAME, paths)


def test_promote_interrupted_after_start_still_keeps_the_previous_release(paths) -> None:
    _prod_v1_staged_v2(paths)
    with _docker(), patch("boxmunge.commands.deploy.smoke_ok",
                          side_effect=KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            run_promote(NAME, paths)
    assert not has_prestage(paths, NAME)
    assert find_rollback_target(paths, NAME).ref == f"{NAME}-{V1}"


def test_a_crash_mid_promote_blocks_unstage_and_stage_until_promote_finishes(
    paths, capsys,
) -> None:
    """A killed promote leaves the kept release flagged: production already
    runs the staged one. Only finishing the promote may proceed."""
    _prod_v1_staged_v2(paths)
    mark_prestage_replaced(paths, NAME)  # what the killed promote left on disk
    place_bundle(paths, timestamp=V3, files={"VERSION": "v3\n"})
    with _docker():
        assert run_unstage(NAME, paths) == 1
        assert run_stage(NAME, paths, ref=V3) == 1
    assert f"promote {NAME}" in capsys.readouterr().err
    assert _version(paths) == "v2\n"
    with _docker():
        assert run_promote(NAME, paths) == 0
    assert find_rollback_target(paths, NAME).ref == f"{NAME}-{V1}"


def test_failed_unstage_keeps_what_a_retry_needs(paths, capsys) -> None:
    _prod_v1_staged_v2(paths)
    override = paths.project_staging_compose_override(NAME)
    base = paths.project_dir(NAME) / "compose.staging-base.yml"
    with _docker(), patch("boxmunge.commands.unstage_cmd.compose_down",
                          side_effect=DockerError("daemon unavailable")):
        assert run_unstage(NAME, paths) == 1
    assert "can retry" in capsys.readouterr().err
    assert staging_exists(NAME, paths)
    assert override.exists() and base.exists()
    assert has_prestage(paths, NAME) and _version(paths) == "v2\n"
    state = read_state(paths.project_staging_state(NAME))
    assert state["active"] is True
    assert state["cleanup_incomplete"] == "daemon unavailable"

    with _docker(), patch("boxmunge.commands.unstage_cmd.compose_down") as down:
        assert run_unstage(NAME, paths) == 0
    assert down.call_args.kwargs["compose_files"] == [
        "compose.staging-base.yml", "compose.boxmunge-staging.yml"]
    assert not override.exists() and not base.exists()
    assert _version(paths) == "v1\n"
    assert read_state(paths.project_staging_state(NAME)) == {"active": False}
