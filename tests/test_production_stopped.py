"""Production never stays stopped because of staging's data copy."""
from __future__ import annotations

from unittest.mock import patch

import pytest
import yaml

from boxmunge.compose_guard import compose_up_checked
from boxmunge.docker_run import DockerError
from boxmunge.pause import write_paused_state
from boxmunge.production_stopped import (
    PROD_FILES, ProductionDownError, mark_stopped, start_again,
)
from boxmunge.staged_release import load_slot, new_meta, slot_dir, write_meta
from tests.deploy_helpers import mark_deployed

P = "shop"


@pytest.fixture
def stopped(paths, fake_containers):
    pdir = paths.project_dir(P)
    pdir.mkdir(parents=True)
    (pdir / "manifest.yml").write_text(yaml.safe_dump({
        "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ", "project": P, "source": "bundle",
        "hosts": ["shop.example.com"], "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}}}))
    (pdir / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
    (pdir / "compose.boxmunge.yml").write_text("services: {}\n")
    mark_deployed(paths, P)
    slot = slot_dir(paths, P)
    (slot / "release").mkdir(parents=True)
    meta = new_meta("bundle", "shop-v2", None)
    write_meta(slot, meta)
    fake_containers.run(P, "web", "sha256:1", running=False)
    return mark_stopped(paths, P, meta, ["shop-web-1"])


def test_the_marker_is_durable(paths, stopped) -> None:
    marker = load_slot(paths, P).production_stopped
    assert marker["containers"] == ["shop-web-1"] and marker["at"]


def test_no_marker_does_nothing(paths) -> None:
    assert start_again(paths, P, component="check-all", alert=True) is False


def test_marker_starts_the_recorded_containers_and_clears(paths, stopped) -> None:
    sent: list[str] = []
    with patch("boxmunge.compose_guard.start_containers") as start, \
            patch("boxmunge.production_stopped.notify", lambda *a, **k: sent.append(a[1])):
        assert start_again(paths, P, component="check-all", alert=True) is True
    start.assert_called_once_with(["shop-web-1"])
    assert load_slot(paths, P).production_stopped is None and sent


def test_no_alert_when_not_asked(paths, stopped) -> None:
    sent: list[str] = []
    with patch("boxmunge.compose_guard.start_containers"), \
            patch("boxmunge.production_stopped.notify", lambda *a, **k: sent.append(a[1])):
        assert start_again(paths, P, component="stage", alert=False) is True
    assert sent == []


def test_a_missing_container_brings_production_up(paths, stopped, fake_containers) -> None:
    fake_containers.remove(P)
    with patch("boxmunge.compose_guard.compose_up") as up, \
            patch("boxmunge.compose_guard.start_containers") as start:
        assert start_again(paths, P, component="recover", alert=False) is True
    up.assert_called_once()
    assert up.call_args.kwargs["compose_files"] == PROD_FILES
    assert up.call_args.kwargs["project_name"] == P
    start.assert_not_called()
    assert load_slot(paths, P).production_stopped is None


def test_failure_keeps_the_marker_and_says_production_is_down(paths, stopped) -> None:
    sent: list[str] = []
    with patch("boxmunge.compose_guard.start_containers", side_effect=DockerError("boom")), \
            patch("boxmunge.production_stopped.notify", lambda *a, **k: sent.append(a[1])), \
            pytest.raises(ProductionDownError, match="docker start shop-web-1"):
        start_again(paths, P, component="stage", alert=False)
    assert load_slot(paths, P).production_stopped is not None
    assert "production is down" in sent[0]


def test_a_blocked_project_stays_down(paths, stopped, capsys) -> None:
    """A pause or quarantine keeps production down on purpose; its lift is a
    production up, which clears the marker."""
    write_paused_state(P, paths, reason="maintenance")
    with patch("boxmunge.compose_guard.start_containers") as start, \
            patch("boxmunge.compose_guard.compose_up") as up:
        assert start_again(paths, P, component="unstage", alert=True) is False
    start.assert_not_called()
    up.assert_not_called()
    assert load_slot(paths, P).production_stopped is not None
    assert "paused" in capsys.readouterr().out


def test_any_production_up_clears_the_marker(paths, stopped) -> None:
    with patch("boxmunge.compose_guard.compose_up"):
        compose_up_checked(paths, P, component="resume", compose_files=PROD_FILES)
    assert load_slot(paths, P).production_stopped is None


def test_a_create_without_start_keeps_the_marker(paths, stopped) -> None:
    """`start=False` creates production's containers but leaves them stopped."""
    with patch("boxmunge.compose_guard.compose_up"):
        compose_up_checked(paths, P, component="deploy", compose_files=PROD_FILES, start=False)
    assert load_slot(paths, P).production_stopped is not None


def test_a_staging_up_keeps_the_marker(paths, stopped) -> None:
    with patch("boxmunge.compose_guard.check_start"), \
            patch("boxmunge.compose_guard.compose_up") as up:
        compose_up_checked(paths, P, component="stage", compose_files=PROD_FILES, staging=True)
    up.assert_called_once()
    assert load_slot(paths, P).production_stopped is not None


def test_a_failed_up_keeps_the_marker(paths, stopped) -> None:
    with patch("boxmunge.compose_guard.compose_up", side_effect=DockerError("boom")), \
            pytest.raises(DockerError):
        compose_up_checked(paths, P, component="resume", compose_files=PROD_FILES)
    assert load_slot(paths, P).production_stopped is not None


def test_an_unreadable_slot_does_not_fail_a_production_up(paths, stopped, capsys) -> None:
    """Production is running by then: the broken slot is said loudly, not
    raised, and is left for the slot's own cores to refuse."""
    (slot_dir(paths, P) / "meta.json").write_text("{not json")
    with patch("boxmunge.compose_guard.compose_up") as up:
        compose_up_checked(paths, P, component="resume", compose_files=PROD_FILES)
    up.assert_called_once()
    err = capsys.readouterr().err
    assert "meta.json" in err and "production is running" in err
    assert "meta.json" in paths.log_file.read_text()
