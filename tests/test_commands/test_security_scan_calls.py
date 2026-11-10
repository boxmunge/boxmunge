# SPDX-License-Identifier: Apache-2.0
"""What one nightly scan costs: Compose, Docker and Trivy calls per project
(deep review E-1, C-7). Counted with stubs around the real scan path."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
import yaml

from boxmunge import docker, docker_containers
from boxmunge.commands import security_scan_core
from boxmunge.commands.security_actions import cmd_security_scan
from boxmunge.commands.security_scan_core import scan_one_project
from boxmunge.cve.kev import KevCatalog
from tests.test_commands.cve_helpers import finding, make_box, scan_result, write_project

_SHARED = "postgres:16"


def _counting(monkeypatch, owner, name: str) -> list:
    calls: list = []
    real = getattr(owner, name)

    def counted(*args, **kwargs):
        calls.append((args, kwargs))
        return real(*args, **kwargs)

    monkeypatch.setattr(owner, name, counted)
    return calls


@pytest.fixture
def fleet(tmp_path, monkeypatch):
    """Two projects that each run their own web image and the same database."""
    paths = make_box(tmp_path, projects=())
    for name in ("aaa", "bbb"):
        write_project(paths, name, services=("web", "db"),
                      images={"web": f"{name}-web:1", "db": _SHARED})
    (paths.state / "projects.txt").write_text("aaa\nbbb\n")
    monkeypatch.setattr("boxmunge.commands.security_actions.refresh_db", lambda: None)
    trivy = []
    monkeypatch.setattr(security_scan_core, "scan_image",
                        lambda ref, timeout: trivy.append(ref) or scan_result(ref))
    return paths, trivy


def test_a_fleet_scan_runs_trivy_once_per_distinct_image(fleet) -> None:
    paths, trivy = fleet
    assert cmd_security_scan([], paths) == 0
    assert sorted(trivy) == ["aaa-web:1", "bbb-web:1", _SHARED]


def test_a_shared_image_is_judged_for_each_project(fleet) -> None:
    paths, _ = fleet
    assert cmd_security_scan([], paths) == 0
    from boxmunge.cve.scan_state import read_scan_state
    for name in ("aaa", "bbb"):
        state = read_scan_state(paths.project_scan_state(name))
        assert sorted(d["image_ref"] for d in state["decisions"]) == sorted(
            [f"{name}-web:1", _SHARED])


def test_a_failed_trivy_run_is_retried_by_the_next_project(fleet, monkeypatch) -> None:
    """Only a result is shared: a scan cut short by one project's budget must
    not leave the next project's copy unscanned."""
    from boxmunge.cve.scanner import ScannerError
    paths, _ = fleet
    tried = []

    def trivy(ref, timeout):
        tried.append(ref)
        if ref == _SHARED and tried.count(ref) == 1:
            raise ScannerError("timed out")
        return scan_result(ref)

    monkeypatch.setattr(security_scan_core, "scan_image", trivy)
    assert cmd_security_scan([], paths) == 1  # aaa is incomplete
    assert tried.count(_SHARED) == 2


def test_a_shared_result_is_used_even_after_the_budget_is_spent(fleet, monkeypatch) -> None:
    paths, trivy = fleet
    monkeypatch.setattr(security_scan_core, "_PROJECT_BUDGET_SECONDS", 0)
    scan = scan_one_project(paths, "aaa", scanned={_SHARED: scan_result(_SHARED)})
    assert trivy == []
    assert scan.skipped_images == ("aaa-web:1",)
    assert [d.image_ref for d in scan.decisions] == [_SHARED]


def test_a_project_scan_resolves_compose_twice_and_lists_containers_once(
    fleet, monkeypatch,
) -> None:
    """The user's own model, then one all-profiles model of the deployed
    files: with no service behind a profile, every service is active."""
    paths, _ = fleet
    compose = _counting(monkeypatch, docker, "compose_config")
    containers = _counting(monkeypatch, docker_containers, "project_containers")
    scan_one_project(paths, "aaa")
    assert len(compose) == 2
    assert [kw.get("all_profiles", False) for _, kw in compose] == [False, True]
    assert len(containers) == 1


def test_a_profiled_service_has_compose_say_which_services_are_active(
    fleet, monkeypatch,
) -> None:
    """COMPOSE_PROFILES (in .env or the environment) activates profiles the
    model does not show, so only Compose can say what `up` starts."""
    paths, _ = fleet
    compose_file = paths.project_dir("aaa") / "compose.yml"
    model = yaml.safe_load(compose_file.read_text())
    model["services"]["worker"] = {"image": "aaa-worker:1", "profiles": ["jobs"]}
    compose_file.write_text(yaml.safe_dump(model))
    compose = _counting(monkeypatch, docker, "compose_config")
    scan = scan_one_project(paths, "aaa")
    assert [kw.get("all_profiles", False) for _, kw in compose] == [False, True, False]
    assert "worker" in "".join(scan.warnings)  # not started: nothing to scan


def test_kev_freshness_is_judged_once_per_scan_not_per_finding(
    tmp_path, monkeypatch,
) -> None:
    paths = make_box(tmp_path, security={"posture": "balanced"})
    now = datetime.now(timezone.utc)
    kev = KevCatalog(frozenset({"CVE-2026-0003"}), now, now, "https://kev.example/feed.json")
    judged = _counting(monkeypatch, KevCatalog, "stale_reason")

    def judgements(findings) -> int:
        judged.clear()
        monkeypatch.setattr(security_scan_core, "scan_image",
                            lambda ref, timeout: scan_result(ref, findings))
        scan_one_project(paths, "demo", kev=kev, defer_new=True)
        return len(judged)

    many = [finding(f"CVE-2026-{n:04d}") for n in range(1, 9)]
    assert judgements(many) == judgements(many[:1]) == 1
