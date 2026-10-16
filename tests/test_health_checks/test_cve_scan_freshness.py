# SPDX-License-Identifier: Apache-2.0
"""The cve-scan health check (audit B-11)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from boxmunge.cve.scan_state import write_scan_state
from boxmunge.health_checks.security import check_cve_scan_freshness
from tests.test_commands.cve_helpers import make_box

_NOW = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)


def _scanned(paths, project, *, hours_ago, unscanned=()):
    path = paths.project_scan_state(project)
    path.parent.mkdir(parents=True, exist_ok=True)
    write_scan_state(path, decisions=(), scanned_at=_NOW - timedelta(hours=hours_ago),
                     unscanned=tuple(unscanned))


def test_fresh_complete_scans_are_ok(tmp_path):
    paths = make_box(tmp_path, projects=("aaa", "bbb"))
    _scanned(paths, "aaa", hours_ago=9)
    _scanned(paths, "bbb", hours_ago=30)
    result = check_cve_scan_freshness(paths, now=_NOW)
    assert result.name == "cve-scan" and result.status == "ok"


def test_stale_never_scanned_and_incomplete_projects_warn(tmp_path):
    paths = make_box(tmp_path, projects=("aaa", "bbb", "ccc", "ddd"))
    _scanned(paths, "aaa", hours_ago=9)
    _scanned(paths, "bbb", hours_ago=50)
    _scanned(paths, "ddd", hours_ago=2, unscanned=["image x:1: scan failed"])
    result = check_cve_scan_freshness(paths, now=_NOW)
    assert result.status == "warn"
    assert "bbb: last scanned 2d 2h ago" in result.detail
    assert "ccc: never scanned" in result.detail
    assert "ddd: last scan incomplete (image x:1: scan failed)" in result.detail
    assert "aaa" not in result.detail


def test_one_fresh_project_does_not_hide_a_stale_one(tmp_path):
    """The fleet view's max(scanned_at) hid stale projects (audit B-11)."""
    paths = make_box(tmp_path, projects=("aaa", "bbb"))
    _scanned(paths, "aaa", hours_ago=1)
    _scanned(paths, "bbb", hours_ago=100)
    assert check_cve_scan_freshness(paths, now=_NOW).status == "warn"


def test_unreadable_scan_state_warns(tmp_path):
    paths = make_box(tmp_path)
    path = paths.project_scan_state("demo")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{truncated")
    result = check_cve_scan_freshness(paths, now=_NOW)
    assert result.status == "warn" and "scan state unreadable" in result.detail


def test_health_report_includes_the_check():
    import inspect

    from boxmunge.commands import health_cmd
    assert "check_cve_scan_freshness(paths)" in inspect.getsource(health_cmd.collect_health)


def test_registered_but_never_deployed_project_is_not_never_scanned(tmp_path):
    """A project registered in state/projects.txt but never deployed has no
    images to scan, so "never scanned" could never clear."""
    paths = make_box(tmp_path, projects=("aaa",))
    with (paths.state / "projects.txt").open("a") as f:
        f.write("ghost\n")
    _scanned(paths, "aaa", hours_ago=1)
    result = check_cve_scan_freshness(paths, now=_NOW)
    assert result.status == "ok", result.detail
    assert "all 1 deployed projects" in result.detail


def test_deployed_project_never_scanned_still_warns(tmp_path):
    paths = make_box(tmp_path, projects=("aaa", "bbb"))
    _scanned(paths, "aaa", hours_ago=1)
    result = check_cve_scan_freshness(paths, now=_NOW)
    assert result.status == "warn" and "bbb: never scanned" in result.detail


def test_no_deployed_projects_is_ok(tmp_path):
    paths = make_box(tmp_path, projects=())
    (paths.state / "projects.txt").write_text("ghost\n")
    result = check_cve_scan_freshness(paths, now=_NOW)
    assert result.status == "ok" and "no projects deployed" in result.detail


def test_malformed_registry_line_warns_and_the_rest_are_still_checked(tmp_path):
    """A bad projects.txt line is named, and does not hide the valid projects."""
    paths = make_box(tmp_path, projects=("aaa", "bbb"))
    registry = paths.state / "projects.txt"
    registry.write_text("aaa\nBAD NAME\nbbb\n")
    _scanned(paths, "aaa", hours_ago=1)
    result = check_cve_scan_freshness(paths, now=_NOW)
    assert result.status == "warn"
    assert f"{registry}:2" in result.detail
    assert "bbb: never scanned" in result.detail
