# SPDX-License-Identifier: Apache-2.0
"""Pure collectors the observe actions share with the CLI. None of them prints."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from boxmunge.backup import BackupKind, parse_snapshot
from boxmunge.commands.check import collect_check
from boxmunge.commands.health_cmd import HealthCheck, HealthReport
from boxmunge.commands.inbox_cmd import collect_inbox
from boxmunge.commands.security_cmd import (
    SecurityViewError, fleet_summary, load_project_security,
)
from boxmunge.commands.security_views import project_cve_status
from boxmunge.commands.status import collect_status, display_rows, run_status


def _deploy(paths, name: str, **manifest) -> None:
    project_dir = paths.projects / name
    project_dir.mkdir(parents=True)
    doc = {"schema_version": 3, "project": name, "services": {"web": {"port": 8080}}}
    doc.update(manifest)
    (project_dir / "manifest.yml").write_text(yaml.safe_dump(doc))


def test_collect_status_reports_failures_without_printing(paths, capsys) -> None:
    _deploy(paths, "good")
    _deploy(paths, "bad")
    (paths.projects / "early").mkdir()
    paths.project_health_state("bad").write_text("{not json")
    snapshot = collect_status(paths)
    assert capsys.readouterr() == ("", "")
    rows = {row["project"]: row for row in snapshot.rows}
    assert rows["bad"]["state"] == "error"
    assert rows["good"]["state"] == "unknown"
    assert rows["early"]["state"] == "pre_registered"
    assert [name for name, _ in snapshot.failures] == ["bad"]


def test_run_status_json_prints_the_collected_rows(paths, capsys) -> None:
    _deploy(paths, "good")
    assert run_status(paths, as_json=True) == 0
    assert capsys.readouterr().out == json.dumps(
        display_rows(collect_status(paths).rows), indent=2) + "\n"


def test_collect_status_without_projects_dir(tmp_path) -> None:
    from boxmunge.paths import BoxPaths
    snapshot = collect_status(BoxPaths(tmp_path / "empty"))
    assert snapshot.projects_dir_exists is False and snapshot.rows == []


def test_collect_check_returns_the_check_json_payload(paths, capsys) -> None:
    _deploy(paths, "app")
    assert collect_check("app", paths) == {"project": "app", "exit_code": 0, "status": "ok"}
    assert collect_check("ghost", paths) == {
        "project": "ghost", "exit_code": 1, "error": "Project not found: ghost"}
    assert capsys.readouterr() == ("", "")


def test_collect_inbox_lists_bundles_newest_first(paths) -> None:
    for name in ("shop-2026-10-14T020000000000.tar.gz", "wiki-2026-10-14T030000000000.tar.gz",
                 "notes.txt"):
        (paths.inbox / name).write_bytes(b"x" * 10)
    bundles = collect_inbox(paths, None)
    assert {b["name"] for b in bundles} == {
        "shop-2026-10-14T020000000000.tar.gz", "wiki-2026-10-14T030000000000.tar.gz"}
    assert all(b["size"] == 10 and str(b["mtime"]).endswith("Z") for b in bundles)
    assert [b["project"] for b in collect_inbox(paths, "wiki")] == ["wiki"]


def test_health_report_dict_and_json_agree() -> None:
    report = HealthReport(checks=[HealthCheck("docker", "ok", "Docker daemon running"),
                                  HealthCheck("caddy", "warn", "starting")])
    assert report.to_dict() == {
        "healthy": False, "exit_code": 1,
        "checks": [{"name": "docker", "status": "ok", "detail": "Docker daemon running"},
                   {"name": "caddy", "status": "warn", "detail": "starting"}],
    }
    assert report.format_json() == json.dumps(report.to_dict(), indent=2)


def test_load_project_security_reads_posture_and_state(paths) -> None:
    _deploy(paths, "shop", security={"posture": "strict"})
    view = load_project_security("shop", paths)
    assert (view.posture, view.quarantined, view.scan_state) == ("strict", False, None)
    assert view.active_suppressions == ()


@pytest.mark.parametrize("manifest_text,message", [
    (None, "Manifest not found"),
])
def test_load_project_security_errors_carry_the_cli_message(paths, manifest_text, message) -> None:
    (paths.projects / "shop").mkdir()
    if manifest_text is not None:
        (paths.projects / "shop" / "manifest.yml").write_text(manifest_text)
    with pytest.raises(SecurityViewError, match=message):
        load_project_security("shop", paths)


def test_fleet_summary_has_its_full_shape_on_an_empty_box(paths) -> None:
    summary = fleet_summary(paths)
    assert summary["projects_count"] == 0
    assert set(summary) == {
        "projects_count", "posture_distribution", "quarantined", "at_risk_running",
        "active_suppressions_count", "active_suppressions_projects",
        "active_suppressions_host", "host_suppressions", "last_fleet_scan",
        "grace", "held_by_breaker",
    }


def test_project_cve_status_puts_quarantine_first() -> None:
    assert project_cve_status(quarantined=True, quarantine_state={}, scan_state=None,
                              dangerously_disable=False) == "QUARANTINED"
    assert project_cve_status(quarantined=False, quarantine_state=None, scan_state=None,
                              dangerously_disable=False) == "NORMAL"


def test_parse_snapshot_is_public() -> None:
    assert parse_snapshot(Path("app-2026-10-14T020000-manual.tar.gz.age"), "app") == (
        "2026-10-14T020000", BackupKind.MANUAL)
    assert parse_snapshot(Path("app-2026-10-14T020000.tar.gz.age"), "app") == (
        "2026-10-14T020000", BackupKind.NIGHTLY)
    assert parse_snapshot(Path("other-2026-10-14T020000.tar.gz.age"), "app") is None
