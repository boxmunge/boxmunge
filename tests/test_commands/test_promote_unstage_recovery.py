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
from boxmunge.release_staging import has_prestage
from boxmunge.state import read_state

from boxmunge.commands.deploy import run_deploy
from boxmunge.project_registry import add_project
from tests.bundle_helpers import HOSTILE_COMPOSE, manifest_text, place_bundle
from tests.test_commands.test_stage_promote_release import V1, V2, _docker, _prod_v1_staged_v2

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
    with _docker(), patch("boxmunge.compose_guard.compose_up", up), \
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
    assert "has no data to restore (backup.type: none)" in err
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


class _Killed(BaseException):
    """Stands in for SIGKILL: nothing in promote may handle it."""


def _kill_after_switch_recorded():
    """A promote killed just after it recorded the switch, before or while
    the containers start: what such a crash leaves on disk."""
    from boxmunge.commands import promote_release
    real = promote_release.mark_prestage_replaced

    def mark_then_die(*args, **kwargs):
        real(*args, **kwargs)
        raise _Killed
    return patch.object(promote_release, "mark_prestage_replaced", mark_then_die)


def _backups_counted(paths, taken: list[str]):
    """Pre-deploy snapshots written as real files; their names in ``taken``."""
    def backup_locked(project_name, paths_, kind=None, manifest=None):
        name = f"{project_name}-snap{len(taken)}.tar.gz.age"
        snap = paths_.project_backups(project_name) / name
        snap.parent.mkdir(parents=True, exist_ok=True)
        snap.write_text("snapshot")
        taken.append(name)
        return 0
    return patch("boxmunge.commands.backup_cmd.backup_locked", backup_locked)


def _staged_with_backups(paths, staged_files=None) -> None:
    add_project(NAME, paths)
    manifest = manifest_text(backup="postgres")
    place_bundle(paths, timestamp=V1, files={"manifest.yml": manifest, "VERSION": "v1\n"})
    place_bundle(paths, timestamp=V2, files={
        "manifest.yml": manifest, "VERSION": "v2\n", **(staged_files or {})})
    with _docker(), _backups_counted(paths, []):
        assert run_deploy(NAME, paths, ref=V1) == 0
        assert run_stage(NAME, paths, ref=V2) == 0


def test_a_crash_mid_promote_blocks_unstage_and_stage_until_promote_finishes(
    paths, capsys,
) -> None:
    _prod_v1_staged_v2(paths)
    with _docker(), _kill_after_switch_recorded(), pytest.raises(_Killed):
        run_promote(NAME, paths)
    place_bundle(paths, timestamp=V3, files={"VERSION": "v3\n"})
    with _docker():
        assert run_unstage(NAME, paths) == 1
        assert run_stage(NAME, paths, ref=V3) == 1
    assert f"promote {NAME}" in capsys.readouterr().err
    assert _version(paths) == "v2\n"
    with _docker():
        assert run_promote(NAME, paths) == 0
    assert find_rollback_target(paths, NAME).ref == f"{NAME}-{V1}"


def test_finishing_a_killed_promote_keeps_the_pre_promotion_snapshot(paths) -> None:
    """The rerun takes no new snapshot: one taken now would hold data the
    staged release may already have changed, and rollback would pair the
    old code with it."""
    _staged_with_backups(paths)
    taken: list[str] = []
    with _docker(), _backups_counted(paths, taken), _kill_after_switch_recorded(), \
            pytest.raises(_Killed):
        run_promote(NAME, paths)
    assert len(taken) == 1
    with _docker(), _backups_counted(paths, taken):
        assert run_promote(NAME, paths) == 0
    assert len(taken) == 1, "the rerun must not snapshot post-switch data"
    target = find_rollback_target(paths, NAME)
    assert (target.ref, target.snapshot) == (f"{NAME}-{V1}", taken[0])


def test_a_failing_rerun_of_a_killed_promote_still_releases_the_stage(paths, capsys) -> None:
    """Production switched before the kill, so however the rerun ends, the
    kept release becomes the previous one: nothing may stay wedged. The
    pre-deploy hook already ran and is not run again."""
    _staged_with_backups(paths, staged_files={
        "manifest.yml": manifest_text(backup="postgres")
        + "deploy:\n  pre_deploy: \"touch pre-deploy-ran\"\n"})
    ran = paths.project_dir(NAME) / "pre-deploy-ran"
    taken: list[str] = []
    with _docker(), _backups_counted(paths, taken), _kill_after_switch_recorded(), \
            pytest.raises(_Killed):
        run_promote(NAME, paths)
    assert ran.exists()
    ran.unlink()
    (paths.project_dir(NAME) / "compose.yml").write_text(HOSTILE_COMPOSE)
    with _docker(), _backups_counted(paths, taken):
        assert run_promote(NAME, paths) == 3
    assert not ran.exists(), "the pre-deploy hook ran again"
    # The killed run may not have reached a container start.
    assert "production may now run" in capsys.readouterr().err
    assert read_state(paths.project_deploy_state(NAME))["current_ref"] == f"{NAME}-{V2}"
    assert not has_prestage(paths, NAME)
    target = find_rollback_target(paths, NAME)
    assert (target.ref, target.snapshot) == (f"{NAME}-{V1}", taken[0])
    with _docker():
        assert run_unstage(NAME, paths) == 0


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


def test_failure_message_never_promises_a_snapshot_that_was_not_taken(
    paths, capsys,
) -> None:
    """The project keeps backups, but the pre-promotion snapshot failed:
    rollback would refuse, and the message says so instead of promising it."""
    _staged_with_backups(paths)
    with _docker(), patch("boxmunge.commands.backup_cmd.backup_locked", return_value=1), \
            patch("boxmunge.commands.deploy.smoke_ok", return_value=False):
        assert run_promote(NAME, paths) == 1
    err = capsys.readouterr().err
    assert f"'rollback {NAME}' is not available: no pre-deploy data snapshot" in err
    assert "restores the data snapshot" not in err


def test_failure_after_the_switch_says_to_unstage(paths, capsys) -> None:
    _prod_v1_staged_v2(paths)
    _failing_promote(paths)
    err = capsys.readouterr().err
    assert f"run 'unstage {NAME}'" in err
    assert "Staging is still live" not in err


def test_promote_whose_staging_teardown_fails_exits_nonzero(paths, capsys) -> None:
    _prod_v1_staged_v2(paths)
    with _docker(), patch("boxmunge.commands.unstage_cmd.compose_down",
                          side_effect=DockerError("daemon unavailable")):
        assert run_promote(NAME, paths) == 1
    err = capsys.readouterr().err
    assert "is live in production" in err and f"Run 'unstage {NAME}'" in err
    assert _version(paths) == "v2\n"
    assert read_state(paths.project_staging_state(NAME))["cleanup_incomplete"]


# Steps prestage_to_previous takes through these helpers, in order: drop
# the old previous metadata, drop the old previous tree, move the kept tree,
# write the new metadata, then discard the kept release (clear the
# tombstone, move it there, remove it).
_KEEP_STEPS = 7


@pytest.mark.parametrize("kill_after", range(1, _KEEP_STEPS + 1))
def test_a_crash_while_keeping_the_previous_release_never_loses_it(
    paths, kill_after,
) -> None:
    from boxmunge.commands import promote_release
    from boxmunge import release_staging
    _staged_with_backups(paths)
    real = {name: getattr(release_staging, name)
            for name in ("_remove", "_move", "atomic_write_text")}
    count = [0]

    def killing(name):
        def step(*args, **kwargs):
            real[name](*args, **kwargs)
            count[0] += 1
            if count[0] == kill_after:
                raise _Killed
        return step

    real_keep = promote_release.prestage_to_previous

    def keep_then_die(*args, **kwargs):
        with patch.multiple(release_staging, **{n: killing(n) for n in real}):
            real_keep(*args, **kwargs)
    taken: list[str] = []
    with _docker(), _backups_counted(paths, taken), \
            patch.object(promote_release, "prestage_to_previous", keep_then_die), \
            pytest.raises(_Killed):
        run_promote(NAME, paths)
    assert count[0] == kill_after
    rerun = has_prestage(paths, NAME)
    with _docker(), _backups_counted(paths, taken):
        if rerun:
            # The kept release still exists: finishing the promote is the way out.
            assert run_promote(NAME, paths) == 0
        # The finished promote tore staging down; otherwise unstage does.
        assert run_unstage(NAME, paths) == (1 if rerun else 0)
    assert not has_prestage(paths, NAME)
    target = find_rollback_target(paths, NAME)
    assert (target.ref, target.snapshot) == (f"{NAME}-{V1}", taken[0])
    assert (target.tree / "VERSION").read_text() == "v1\n"
    assert _version(paths) == "v2\n"
