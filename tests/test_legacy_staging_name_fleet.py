"""#122: a project directory named `<x>-staging` (registered before 0.10.1
reserved the suffix) is reported as unreadable, with the rename hint, by
every fleet loop; it never stops the loop with an InvalidProjectName
traceback."""
from __future__ import annotations

import json

import pytest
import yaml

from boxmunge.paths import BoxPaths

LEGACY = "site-staging"
HINT = "Choose a name without the suffix"


def _project(paths: BoxPaths, name: str) -> None:
    d = paths.projects / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "manifest.yml").write_text(yaml.safe_dump({
        "schema_version": 3, "id": "01TEST", "project": name, "source": "bundle",
        "hosts": [f"{name}.example.com"],
        "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
    }))


@pytest.fixture
def box(paths: BoxPaths) -> BoxPaths:
    paths.config_file.parent.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text("hostname: box.example.com\nadmin_email: a@b.c\n")
    _project(paths, "aaa")
    _project(paths, LEGACY)
    return paths


@pytest.mark.usefixtures("docker_down")
@pytest.mark.parametrize("registered", [True, False], ids=["registry", "no-registry"])
def test_health_reports_the_legacy_name_and_finishes(box: BoxPaths, capsys,
                                                     registered: bool) -> None:
    from boxmunge.commands.health_cmd import run_health
    if registered:
        (box.state / "projects.txt").write_text(f"aaa\n{LEGACY}\n")
    run_health(box, as_json=True)
    report = json.loads(capsys.readouterr().out)
    lifecycle = next(c for c in report["checks"] if c["name"] == "lifecycle")
    assert lifecycle["status"] == "warn"  # exit 2 would roll back an upgrade
    assert LEGACY in lifecycle["detail"] and HINT in lifecycle["detail"]


def test_lifecycle_still_reports_the_other_projects(box: BoxPaths) -> None:
    from boxmunge.health_checks.projects import check_lifecycle_blocked
    from boxmunge.pause import write_paused_state
    write_paused_state("aaa", box)
    check = check_lifecycle_blocked(box)
    assert "aaa" in check.detail      # reached past the legacy dir
    assert LEGACY in check.detail


def test_registry_migration_reports_a_legacy_dir_instead_of_registering_it(
        box: BoxPaths) -> None:
    from boxmunge.project_registry import deployed_among, read_registry
    read = read_registry(box)
    assert read.names == {"aaa"}
    assert len(read.problems) == 1 and LEGACY in read.problems[0] and HINT in read.problems[0]
    # Written as a line of its own, so every later read reports it too.
    assert (box.state / "projects.txt").read_text().splitlines() == ["aaa", LEGACY]
    assert read_registry(box) == read
    assert deployed_among(read.names, box) == ["aaa"]


def _quarantined_aaa(box: BoxPaths) -> None:
    path = box.project_scan_state("aaa")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"scanned_at": "2026-05-30T00:00:00+00:00", "decisions": [
        {"image_ref": "aaa:1", "findings": [
            {"cve_id": "CVE-2026-1001", "effective_severity": "High",
             "disposition": "quarantine"}]}]}))


def test_suppress_current_host_reports_the_legacy_dir_and_unions_the_rest(
        box: BoxPaths, capsys) -> None:
    from boxmunge.commands.security_suppress_targets import (
        all_currently_quarantining_cves,
    )
    _quarantined_aaa(box)
    assert all_currently_quarantining_cves(box) == (["CVE-2026-1001"], [LEGACY])
    err = capsys.readouterr().err
    assert LEGACY in err and HINT in err
    assert "left out" in err


def test_suppress_current_host_writes_the_rest_and_exits_nonzero(
        box: BoxPaths, capsys, monkeypatch) -> None:
    """fleet.py's contract: a project the loop could not process shows in
    the exit code, after the others were handled."""
    from datetime import date, timedelta
    from boxmunge.commands.security_suppress import cmd_security_suppress
    monkeypatch.setenv("USER", "jon")
    _quarantined_aaa(box)
    until = (date.today() + timedelta(days=30)).isoformat()
    rc = cmd_security_suppress(
        ["--current", "--host", "--until", until, "--reason", "fleet-wide ack"], box)
    assert rc == 1
    assert "CVE-2026-1001" in box.host_suppressions.read_text()
    assert LEGACY in capsys.readouterr().err


def test_fleet_security_view_lists_the_legacy_dir_as_unreadable(box: BoxPaths) -> None:
    from boxmunge.commands.security_cmd import fleet_summary
    (box.state / "projects.txt").write_text(f"aaa\n{LEGACY}\n")
    summary = fleet_summary(box)
    unreadable = summary["unreadable"]
    assert any(LEGACY in u["error"] and HINT in u["error"] for u in unreadable)


def test_suppress_current_host_with_only_unreadable_projects_says_so(
        box: BoxPaths, capsys, monkeypatch) -> None:
    from datetime import date, timedelta
    from boxmunge.commands.security_suppress import cmd_security_suppress
    monkeypatch.setenv("USER", "jon")
    until = (date.today() + timedelta(days=30)).isoformat()
    rc = cmd_security_suppress(
        ["--current", "--host", "--until", until, "--reason", "fleet-wide ack"], box)
    assert rc == 1
    err = capsys.readouterr().err
    assert f"{LEGACY} could not be read" in err and "security scan" not in err
    assert not box.host_suppressions.exists()
