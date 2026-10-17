"""The tick, recover and pause act on a production_stopped marker."""
from __future__ import annotations

from unittest.mock import patch

from boxmunge.commands.check import _check_one
from boxmunge.commands.pause_cmd import pause_locked
from boxmunge.commands.recover_cmd import recover_locked, run_recover
from boxmunge.docker_run import DockerError
from boxmunge.release_txn import open_txn
from boxmunge.staged_release import load_slot, slot_dir, update_meta
from boxmunge.state import read_state
from tests.stage_helpers import V1, prod_and_stage


def _stopped(paths, fake_containers):
    prod_and_stage(paths)
    fake_containers.run("myapp", "web", "sha256:1", running=False)
    update_meta(paths, "myapp", load_slot(paths, "myapp"),
                production_stopped={"at": "t", "containers": ["myapp-web-1"]})


def _break_slot(paths) -> None:
    (slot_dir(paths, "myapp") / "meta.json").write_text("{not json")


def _last_started(paths) -> str | None:
    return read_state(paths.project_deploy_state("myapp")).get("last_started_at")


def test_tick_starts_production_again(paths, fake_containers, capsys) -> None:
    """The app may still be booting: smoke runs on the next tick, not now.
    last_started_at is bumped, as after a deploy, resume or recover."""
    _stopped(paths, fake_containers)
    before = _last_started(paths)
    with patch("boxmunge.compose_guard.start_containers") as start, \
            patch("boxmunge.production_stopped.notify"), \
            patch("boxmunge.commands.check.run_check") as check, \
            patch("boxmunge.commands.health_state.compose_down") as down:
        assert _check_one("myapp", paths, read_only=False) == 1
    start.assert_called_once_with(["myapp-web-1"])
    check.assert_not_called()
    down.assert_not_called()
    assert load_slot(paths, "myapp").production_stopped is None
    assert _last_started(paths) != before
    assert "started again after staging's data copy; checked next tick" in \
        capsys.readouterr().out


def test_tick_with_a_marker_and_an_open_install_reports_the_install(paths, fake_containers,
                                                                    capsys) -> None:
    """Every start waits for the install, so trying one would only page
    PRODUCTION IS DOWN on every tick; the marker is found again once the
    install is closed."""
    _stopped(paths, fake_containers)
    open_txn(paths, "myapp", source="bundle", ref="myapp-x", replaced_ref=f"myapp-{V1}",
             staged_id=None, snapshot="")
    with patch("boxmunge.compose_guard.start_containers") as start, \
            patch("boxmunge.production_stopped.notify") as page, \
            patch("boxmunge.compose_guard.notify"):
        assert _check_one("myapp", paths, read_only=False) == 1
    start.assert_not_called()
    page.assert_not_called()
    assert "install open" in capsys.readouterr().out
    assert load_slot(paths, "myapp").production_stopped is not None


def test_a_start_that_keeps_failing_pages_once(paths, fake_containers, capsys) -> None:
    _stopped(paths, fake_containers)
    with patch("boxmunge.compose_guard.start_containers", side_effect=DockerError("no")), \
            patch("boxmunge.production_stopped.notify") as direct, \
            patch("boxmunge.project_alerts.notify", return_value=True) as page:
        assert _check_one("myapp", paths, read_only=False) == 2
        assert _check_one("myapp", paths, read_only=False) == 2
    direct.assert_not_called()
    assert page.call_count == 1 and page.call_args.kwargs["priority"] == 1
    assert capsys.readouterr().err.count("ERROR: PRODUCTION IS DOWN") == 2  # said every tick


def test_a_failure_after_a_success_pages_again(paths, fake_containers) -> None:
    _stopped(paths, fake_containers)
    marker = load_slot(paths, "myapp").production_stopped
    with patch("boxmunge.production_stopped.notify"), \
            patch("boxmunge.project_alerts.notify", return_value=True) as page:
        with patch("boxmunge.compose_guard.start_containers", side_effect=DockerError("no")):
            _check_one("myapp", paths, read_only=False)
        with patch("boxmunge.compose_guard.start_containers"):
            assert _check_one("myapp", paths, read_only=False) == 1
        update_meta(paths, "myapp", load_slot(paths, "myapp"), production_stopped=marker)
        with patch("boxmunge.compose_guard.start_containers", side_effect=DockerError("no")):
            _check_one("myapp", paths, read_only=False)
    assert page.call_count == 2


def test_a_start_outside_the_tick_clears_its_alert(paths, fake_containers) -> None:
    """recover (or stage, unstage) starting production again forgets the
    tick's production-down alert, so a relapse is paged again."""
    from boxmunge.commands.check_holds import DOWN_ALERT
    from boxmunge.project_alerts import alert_state
    _stopped(paths, fake_containers)
    marker = load_slot(paths, "myapp").production_stopped
    with patch("boxmunge.production_stopped.notify"), \
            patch("boxmunge.project_alerts.notify", return_value=True) as page:
        with patch("boxmunge.compose_guard.start_containers", side_effect=DockerError("no")):
            _check_one("myapp", paths, read_only=False)
        assert alert_state(paths, "myapp", DOWN_ALERT).exists()
        with patch("boxmunge.compose_guard.start_containers"):
            assert recover_locked("myapp", paths) == 0
        assert not alert_state(paths, "myapp", DOWN_ALERT).exists()
        update_meta(paths, "myapp", load_slot(paths, "myapp"), production_stopped=marker)
        with patch("boxmunge.compose_guard.start_containers", side_effect=DockerError("no")):
            _check_one("myapp", paths, read_only=False)
    assert page.call_count == 2


def test_tick_never_runs_its_critical_down_while_the_marker_stands(paths, fake_containers) -> None:
    _stopped(paths, fake_containers)
    with patch("boxmunge.compose_guard.start_containers", side_effect=DockerError("no")), \
            patch("boxmunge.production_stopped.notify"), \
            patch("boxmunge.commands.health_state.compose_down") as down:
        assert _check_one("myapp", paths, read_only=False) == 2
    down.assert_not_called()
    assert load_slot(paths, "myapp").production_stopped is not None


def test_read_only_tick_reports_the_marker_and_starts_nothing(paths, fake_containers,
                                                              capsys) -> None:
    _stopped(paths, fake_containers)
    with patch("boxmunge.compose_guard.start_containers") as start, \
            patch("boxmunge.commands.check.run_check") as check:
        assert _check_one("myapp", paths, read_only=True) == 2
    start.assert_not_called()
    check.assert_not_called()
    assert "production stopped for staging's data copy" in capsys.readouterr().out
    assert load_slot(paths, "myapp").production_stopped is not None


def test_tick_alerts_an_unreadable_slot_once(paths, fake_containers, capsys) -> None:
    """The slot cannot name what was stopped: the tick leaves production
    alone (no smoke, no critical down) and says so, paging once per error
    rather than on every tick."""
    prod_and_stage(paths)
    _break_slot(paths)
    with patch("boxmunge.project_alerts.notify", return_value=True) as page, \
            patch("boxmunge.production_stopped.notify") as down_page, \
            patch("boxmunge.commands.check.run_check") as check, \
            patch("boxmunge.commands.health_state.compose_down") as down:
        assert _check_one("myapp", paths, read_only=False) == 2
        assert _check_one("myapp", paths, read_only=False) == 2
    assert page.call_count == 1
    assert page.call_args.kwargs["priority"] == 1
    down_page.assert_not_called()
    check.assert_not_called()
    down.assert_not_called()
    out = capsys.readouterr().out
    assert "staged slot cannot be read" in out and "recover myapp" in out


def test_tick_alerts_again_after_the_slot_was_readable(paths, fake_containers) -> None:
    prod_and_stage(paths)
    meta_text = (slot_dir(paths, "myapp") / "meta.json").read_text()
    with patch("boxmunge.project_alerts.notify", return_value=True) as page, \
            patch("boxmunge.commands.check.run_check", return_value=0):
        _break_slot(paths)
        _check_one("myapp", paths, read_only=False)
        (slot_dir(paths, "myapp") / "meta.json").write_text(meta_text)
        assert _check_one("myapp", paths, read_only=False) == 0
        _break_slot(paths)
        _check_one("myapp", paths, read_only=False)
    assert page.call_count == 2


def test_read_only_tick_reports_an_unreadable_slot_without_alerting(paths) -> None:
    prod_and_stage(paths)
    _break_slot(paths)
    with patch("boxmunge.project_alerts.notify") as page, \
            patch("boxmunge.commands.check.run_check") as check:
        assert _check_one("myapp", paths, read_only=True) == 2
    page.assert_not_called()
    check.assert_not_called()


def test_tick_leaves_an_open_install_alone(paths, fake_containers, capsys) -> None:
    """An install left open may already have refreshed boxmunge-scripts in
    place: smoke would run new scripts against old containers, and a
    critical result would take production down mid-install."""
    prod_and_stage(paths)
    open_txn(paths, "myapp", source="bundle", ref="myapp-x", replaced_ref=f"myapp-{V1}",
             staged_id=None, snapshot="")
    with patch("boxmunge.commands.check.run_check") as check, \
            patch("boxmunge.commands.check.update_health_state") as health, \
            patch("boxmunge.commands.health_state.compose_down") as down:
        assert _check_one("myapp", paths, read_only=False) == 1
    check.assert_not_called()
    health.assert_not_called()
    down.assert_not_called()
    out = capsys.readouterr().out
    assert "install open" in out and "prod-deploy myapp --abandon" in out


def test_recover_starts_production_again(paths, fake_containers) -> None:
    _stopped(paths, fake_containers)
    before = _last_started(paths)
    with patch("boxmunge.compose_guard.start_containers") as start, \
            patch("boxmunge.production_stopped.notify"):
        assert recover_locked("myapp", paths) == 0
    start.assert_called_once()
    assert _last_started(paths) != before


def test_recover_reads_the_slot_once(paths, fake_containers) -> None:
    import boxmunge.commands.recover_cmd as recover_cmd
    import boxmunge.production_stopped as production_stopped
    _stopped(paths, fake_containers)
    with patch("boxmunge.compose_guard.start_containers"), \
            patch("boxmunge.production_stopped.notify"), \
            patch.object(recover_cmd, "load_slot", wraps=recover_cmd.load_slot) as here, \
            patch.object(production_stopped, "load_slot",
                         wraps=production_stopped.load_slot) as there:
        assert recover_locked("myapp", paths) == 0
    assert here.call_count == 1
    there.assert_not_called()


def test_recover_prompt_names_what_it_starts(paths, fake_containers, capsys) -> None:
    _stopped(paths, fake_containers)
    with patch("builtins.input", return_value="n"):
        assert run_recover("myapp", paths) == 1
    assert "Start the production containers that staging's data copy stopped" in \
        capsys.readouterr().out
    _break_slot(paths)
    with patch("builtins.input", return_value="n"):
        assert run_recover("myapp", paths) == 1
    assert "Bring production up with its compose files" in capsys.readouterr().out


def test_recover_entry_accepts_a_copy_stop(paths, fake_containers, capsys) -> None:
    """recover is the remedy start_again names: its pre-lock check must not
    refuse a project the health monitor did not stop."""
    _stopped(paths, fake_containers)
    with patch("boxmunge.compose_guard.start_containers") as start, \
            patch("boxmunge.production_stopped.notify"):
        assert run_recover("myapp", paths, yes=True) == 0
    start.assert_called_once_with(["myapp-web-1"])
    assert "production started again after staging's data copy" in capsys.readouterr().out


def test_recover_with_an_unreadable_slot_starts_production(paths, fake_containers,
                                                           capsys) -> None:
    """What was stopped cannot be named, so recover starts production with
    its own compose files, as the unreadable-slot messages tell the operator."""
    prod_and_stage(paths)
    _break_slot(paths)
    with patch("boxmunge.compose_guard.compose_up") as up, \
            patch("boxmunge.compose_guard.notify"), \
            patch("boxmunge.commands.recover_cmd.caddy_reload"), \
            patch("boxmunge.commands.recover_cmd.run_smoke", return_value=(True, "ok")):
        assert run_recover("myapp", paths, yes=True) == 0
    assert up.call_args.kwargs["project_name"] == "myapp"
    assert "staged slot cannot be read" in capsys.readouterr().out


def test_recover_still_refuses_a_running_project(paths, capsys) -> None:
    prod_and_stage(paths)
    assert run_recover("myapp", paths, yes=True) == 1
    assert "Nothing to recover" in capsys.readouterr().err


def test_pause_takes_over_the_stop(paths, fake_containers) -> None:
    _stopped(paths, fake_containers)
    with patch("boxmunge.commands.pause_cmd.compose_stop"), \
            patch("boxmunge.commands.pause_cmd.caddy_reload"):
        assert pause_locked("myapp", paths, reason="maintenance") == 0
    assert load_slot(paths, "myapp").production_stopped is None


def test_a_failed_pause_stop_keeps_the_marker(paths, fake_containers) -> None:
    _stopped(paths, fake_containers)
    with patch("boxmunge.commands.pause_cmd.compose_stop", side_effect=DockerError("no")), \
            patch("boxmunge.commands.pause_cmd.caddy_reload"):
        assert pause_locked("myapp", paths, reason="maintenance") == 1
    assert load_slot(paths, "myapp").production_stopped is not None


def test_pause_with_an_unreadable_slot_still_pauses(paths, capsys) -> None:
    prod_and_stage(paths)
    _break_slot(paths)
    with patch("boxmunge.commands.pause_cmd.compose_stop"), \
            patch("boxmunge.commands.pause_cmd.caddy_reload"):
        assert pause_locked("myapp", paths, reason="maintenance") == 0
    assert "staged slot could not be read" in capsys.readouterr().err
