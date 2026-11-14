"""A deployed project whose manifest vanished stays visible and fails the fleet."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import pytest

from boxmunge.backup_evidence import deployed_projects
from boxmunge.commands.check_all import run_check_all
from boxmunge.health_checks.backup_freshness import check_backup_freshness
from boxmunge.health_checks.projects import check_project_containers
from boxmunge.health_checks.security import check_cve_scan_freshness
from boxmunge.project_inventory import Inventory, classify
from boxmunge.project_registry import add_project, deployed_among, read_registry
from tests.backup_alert_helpers import backed_up_project

DAMAGED, HEALTHY, WAITING = "alpha", "omega", "pending-one"


def _deployed(paths, name):
    pdir = backed_up_project(paths, name)
    paths.project_deploy_state(name).parent.mkdir(parents=True, exist_ok=True)
    paths.project_deploy_state(name).write_text(json.dumps({"deployed_at": "2026-11-01T00:00:00+00:00"}))
    add_project(name, paths)
    return pdir


@pytest.fixture
def fleet(paths):
    bad = _deployed(paths, DAMAGED)
    _deployed(paths, HEALTHY)
    paths.project_dir(WAITING).mkdir(parents=True)
    add_project(WAITING, paths)
    return bad


def test_classification(paths, fleet) -> None:
    assert classify(WAITING, paths) is Inventory.AWAITING
    assert classify(HEALTHY, paths) is Inventory.DEPLOYED
    (fleet / "manifest.yml").unlink()
    assert classify(DAMAGED, paths) is Inventory.DAMAGED


def test_a_dangling_manifest_link_is_still_deployed(paths, fleet) -> None:
    (fleet / "manifest.yml").unlink()
    os.symlink("repo/manifest.yml", fleet / "manifest.yml")
    assert classify(DAMAGED, paths) is Inventory.DEPLOYED


@pytest.mark.parametrize("damage", ["deleted", "dangling"])
def test_discovery_keeps_the_damaged_project_and_skips_the_waiting_one(
        paths, fleet, damage) -> None:
    (fleet / "manifest.yml").unlink()
    if damage == "dangling":
        os.symlink("repo/manifest.yml", fleet / "manifest.yml")
    names = read_registry(paths).names
    assert deployed_among(names, paths) == [DAMAGED, HEALTHY]
    assert deployed_projects(paths) == [DAMAGED, HEALTHY]


def test_health_checks_warn_about_the_damaged_project(paths, fleet, monkeypatch) -> None:
    (fleet / "manifest.yml").unlink()
    monkeypatch.setattr("boxmunge.health_checks.projects.compose_inventory.running_inventory",
                        lambda **k: type("R", (), {"is_running": lambda s, n: True})())
    now = datetime.now(timezone.utc)
    for check in (check_backup_freshness(paths, now=now), check_cve_scan_freshness(paths, now=now),
                  check_project_containers(paths)):
        assert check.status == "warn" and DAMAGED in check.detail, check
        assert WAITING not in check.detail


def test_check_all_visits_the_later_project_and_fails(paths, fleet, monkeypatch, capsys) -> None:
    (fleet / "manifest.yml").unlink()
    visited = []
    # The damaged project goes through the real per-project boundary.
    from boxmunge.commands import check_all
    real = check_all._check_one
    monkeypatch.setattr("boxmunge.commands.check_all._check_project",
                        lambda name, p, ro, tick: (visited.append(name), real(name, p, ro, tick))[1]
                        if name == DAMAGED else visited.append(name) or 0)
    assert run_check_all(paths, read_only=True) == 1
    assert visited == [DAMAGED, HEALTHY]
    assert DAMAGED in capsys.readouterr().err


def test_backup_all_reports_the_damaged_project_and_still_backs_up_the_rest(
        paths, fleet, monkeypatch) -> None:
    from boxmunge.commands import backup_cmd
    (fleet / "manifest.yml").unlink()
    seen = []
    real = backup_cmd._attempt_isolated
    monkeypatch.setattr(backup_cmd, "_attempt_isolated",
                        lambda name, p: seen.append(name) or real(name, p)
                        if name == DAMAGED else seen.append(name) or backup_cmd.BackupAttemptResult.OK)
    monkeypatch.setattr(backup_cmd, "notify", lambda *a, **k: True)
    assert backup_cmd.run_backup_all(paths) == 1
    assert seen == [DAMAGED, HEALTHY]


def test_status_shows_the_damaged_project_as_an_error_not_pre_registered(paths, fleet) -> None:
    from boxmunge.commands.status import collect_status
    (fleet / "manifest.yml").unlink()
    snap = collect_status(paths)
    rows = {r["project"]: r for r in snap.rows}
    assert rows[DAMAGED]["state"] != "pre_registered"
    assert rows[WAITING]["state"] == "pre_registered"
    assert any(n == DAMAGED for n, _ in snap.failures)
