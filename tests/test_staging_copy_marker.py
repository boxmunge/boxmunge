"""The copy records production_stopped durably before the stop."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from boxmunge import staging_data
from boxmunge.compose_guard import ComposeRefused
from boxmunge.docker_run import DockerError
from boxmunge.production_stopped import ProductionDownError
from boxmunge.staged_release import drop_slot, load_slot, new_meta, slot_dir, write_meta
from boxmunge.staging_copy_plan import CopyPlan, StagingDataError, Store

P = "shop"


@pytest.fixture
def running(paths, fake_containers):
    (slot_dir(paths, P) / "release").mkdir(parents=True)
    write_meta(slot_dir(paths, P), new_meta("bundle", "shop-v2", None))
    fake_containers.run(P, "web", "sha256:1")
    fake_containers.remove(f"{P}-staging")
    src = paths.project_dir(P) / "uploads"
    src.mkdir(parents=True)
    plan = CopyPlan(pairs=[(Store("bind", "./uploads", str(src)),
                            Store("bind", "./uploads", str(paths.project_dir(P) / "uploads-staging")))])
    return plan


def _stops(run) -> list:
    return [c for c in run.call_args_list if c.args[0][:2] == ["docker", "stop"]]


def test_marker_before_stop_and_cleared_after(paths, running) -> None:
    order: list[str] = []

    def run(cmd, **kw):
        if cmd[:2] == ["docker", "stop"]:
            order.append("stop:" + str(load_slot(paths, P).production_stopped is not None))

    with patch.object(staging_data, "check_containers_start"), \
            patch.object(staging_data, "_run", run), patch.object(staging_data, "run_helper"), \
            patch("boxmunge.production_stopped.start_containers_checked") as start:
        staging_data.copy_production_data(paths, P, running)
    assert order == ["stop:True"]
    start.assert_called_once()
    assert start.call_args.args[2] == ["shop-web-1"]
    assert load_slot(paths, P).production_stopped is None


def test_failed_copy_still_starts_production(paths, running) -> None:
    with patch.object(staging_data, "check_containers_start"), patch.object(staging_data, "_run"), \
            patch.object(staging_data, "run_helper", side_effect=DockerError("disk full")), \
            patch("boxmunge.production_stopped.start_containers_checked") as start, \
            pytest.raises(DockerError, match="disk full"):
        staging_data.copy_production_data(paths, P, running)
    start.assert_called_once()
    assert load_slot(paths, P).production_stopped is None


def test_failed_stop_still_starts_production(paths, running) -> None:
    with patch.object(staging_data, "check_containers_start"), \
            patch.object(staging_data, "_run", side_effect=DockerError("did not stop")), \
            patch.object(staging_data, "run_helper") as helper, \
            patch("boxmunge.production_stopped.start_containers_checked") as start, \
            pytest.raises(DockerError, match="did not stop"):
        staging_data.copy_production_data(paths, P, running)
    helper.assert_not_called()
    start.assert_called_once()
    assert load_slot(paths, P).production_stopped is None


def test_production_left_down_keeps_the_marker_and_says_so(paths, running, capsys) -> None:
    with patch.object(staging_data, "check_containers_start"), patch.object(staging_data, "_run"), \
            patch.object(staging_data, "run_helper", side_effect=DockerError("No space")), \
            patch("boxmunge.production_stopped.start_containers_checked",
                  side_effect=DockerError("Cannot connect to the Docker daemon")), \
            pytest.raises(ProductionDownError) as raised:
        staging_data.copy_production_data(paths, P, running)
    # The copy's failure stays in the chain; the marker stays for a finder.
    assert "No space" in str(raised.value.__cause__.__context__)
    assert "PRODUCTION IS DOWN" in capsys.readouterr().err
    assert load_slot(paths, P).production_stopped["containers"] == ["shop-web-1"]


def test_refused_start_check_stops_nothing(paths, running) -> None:
    with patch.object(staging_data, "check_containers_start", side_effect=ComposeRefused("no")), \
            patch.object(staging_data, "_run") as run, pytest.raises(ComposeRefused):
        staging_data.copy_production_data(paths, P, running)
    assert not _stops(run)
    assert load_slot(paths, P).production_stopped is None


def test_a_failed_marker_write_stops_nothing(paths, running) -> None:
    with patch.object(staging_data, "check_containers_start"), \
            patch.object(staging_data, "mark_stopped", side_effect=OSError("read-only fs")), \
            patch.object(staging_data, "_run") as run, \
            patch("boxmunge.production_stopped.start_containers_checked") as start, \
            pytest.raises(OSError, match="read-only fs"):
        staging_data.copy_production_data(paths, P, running)
    assert not _stops(run)
    start.assert_not_called()


def test_no_slot_to_record_the_stop_in_stops_nothing(paths, running) -> None:
    drop_slot(paths, P)
    with patch.object(staging_data, "check_containers_start"), \
            patch.object(staging_data, "_run") as run, \
            pytest.raises(StagingDataError, match="no staged slot"):
        staging_data.copy_production_data(paths, P, running)
    assert not _stops(run)


def test_production_not_running_is_not_marked(paths, running, fake_containers) -> None:
    fake_containers.remove(P)
    with patch.object(staging_data, "_run") as run, \
            patch.object(staging_data, "run_helper") as helper:
        staging_data.copy_production_data(paths, P, running)
    assert not _stops(run)
    helper.assert_called_once()
    assert load_slot(paths, P).production_stopped is None


def test_prestage_copy_starts_production_without_a_slot(paths, running) -> None:
    """The interim stage layout has no slot to record the stop in."""
    drop_slot(paths, P)
    with patch.object(staging_data, "check_containers_start"), \
            patch.object(staging_data, "_run") as run, patch.object(staging_data, "run_helper"), \
            patch.object(staging_data, "start_containers_checked") as start:
        staging_data.copy_production_data(paths, P, running, prestage=True)
    assert len(_stops(run)) == 1
    start.assert_called_once()
    assert start.call_args.args[2] == ["shop-web-1"]
