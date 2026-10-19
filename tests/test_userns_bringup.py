"""Quiesce order; bring-up keeps failed projects on the maintenance page."""
from __future__ import annotations

import json

import pytest

from boxmunge.commands.health_state import MONITOR_STOPPED
from boxmunge.lifecycle import Block, BlockReason
from boxmunge.userns import bringup as bu
from boxmunge.userns.inventory import ContainerEntry, Inventory
from boxmunge.userns.journal import FORWARD, Journal


def _c(name, project, service="app", running=True):
    return ContainerEntry(name, name, project, service, "sha256:i", running, False, "", "", "",
                          "", [])


def _inv():
    return Inventory("overlay2", "", "/v", "29.9.0", projects=["good", "bad", "held"],
                     containers=[_c("boxmunge-caddy", "caddy"), _c("boxmunge-system", "system"),
                                 _c("good-app-1", "good"), _c("bad-app-1", "bad"),
                                 _c("idle", "good", "worker", running=False)])


def test_quiesce_stops_projects_system_then_caddy(monkeypatch) -> None:
    calls = []

    def run(cmd, capture=False, timeout=None):
        if cmd[:2] == ["docker", "ps"]:  # idle is stopped; bad-app-1 is gone already
            return type("R", (), {"stdout": "boxmunge-caddy\nboxmunge-system\ngood-app-1\n"})()
        calls.append(cmd[4:])
    monkeypatch.setattr(bu, "_run", run)
    assert bu.quiesce(_inv()) == ["good-app-1", "boxmunge-system", "boxmunge-caddy"]
    assert calls == [["good-app-1"], ["boxmunge-system"], ["boxmunge-caddy"]]


@pytest.fixture
def box(paths, monkeypatch):
    for p in ("good", "bad", "held"):
        paths.project_dir(p).mkdir(parents=True)
        paths.project_manifest(p).write_text(f"project: {p}\nhosts: [{p}.example.com]\n")
    events = []
    monkeypatch.setattr(bu, "_run", lambda cmd, capture=False, timeout=None: None)
    monkeypatch.setattr(bu, "compose_up_platform",
                        lambda d, f, stack, build: events.append(("platform", stack, build)))
    monkeypatch.setattr(bu, "connect", lambda paths: events.append(("connect",)))
    monkeypatch.setattr(bu, "caddy_reload", lambda *a: events.append(("reload",)))
    monkeypatch.setattr(bu, "load_manifest", lambda path: {"project": path.parent.name,
                                                           "hosts": [f"{path.parent.name}.x"]})
    monkeypatch.setattr(bu, "prepare_compose_override",
                        lambda paths, m, component: events.append(("overlay", m["project"])))
    held = Block(reason=BlockReason.PAUSED, detail={}, refuse_message="", skip_message="")
    monkeypatch.setattr(bu, "lifecycle_block", lambda p, paths: held if p == "held" else None)

    def up(paths, p, **kw):
        events.append(("up", p, tuple(kw["services"]), kw["record"], kw["build"]))
        if p == "bad":
            raise bu.DockerError("container exited")
    monkeypatch.setattr(bu, "compose_up_checked", up)
    monkeypatch.setattr(bu, "smoke_ok", lambda *a: True)
    monkeypatch.setattr(bu, "prepare_caddy_config",
                        lambda paths, m: events.append(("route", m["project"])))
    return events


def test_bring_up_routes_healthy_projects_and_keeps_failures_on_maintenance(paths, box) -> None:
    events = box
    j = Journal(FORWARD, "rebuilt", 1048576)
    saved = []
    results = bu.bring_up(paths, _inv(), j, lambda: saved.append(dict(j.items)),
                          component="userns-migrate")
    assert results["good"] == "up" and results["bad"] == "failed: container exited"
    assert results["held"] == "left paused" and ("overlay", "held") in events
    assert ("route", "good") in events and ("route", "bad") not in events
    assert events[:2] == [("platform", "system", False), ("connect",)]
    assert events.index(("platform", "caddy", False)) < events.index(("up", "good", ("app",),
                                                                      True, False))
    assert "maintenance" in paths.project_caddy_site("bad").read_text()
    assert not paths.project_caddy_site("held").exists()  # pause's own page stays
    assert len(saved) == 3


def test_a_resumed_bring_up_never_redoes_a_project_that_came_up(paths, box) -> None:
    events = box
    j = Journal(FORWARD, "rebuilt", 1048576, items={"project:good": "up"})
    bu.bring_up(paths, _inv(), j, lambda: None, component="userns-migrate")
    assert not [e for e in events if e[0] == "up" and e[1] == "good"]
    assert not paths.project_caddy_site("good").exists()  # its routes were left alone


def test_a_project_whose_smoke_fails_stays_behind_the_page(paths, box, monkeypatch) -> None:
    monkeypatch.setattr(bu, "smoke_ok", lambda p, *a: p != "good")
    j = Journal(FORWARD, "rebuilt", 1048576)
    assert bu.bring_up(paths, _inv(), j, lambda: None,
                       component="userns-migrate")["good"].startswith("failed: its smoke")
    assert "maintenance" in paths.project_caddy_site("good").read_text()


def test_a_missing_system_image_is_rebuilt(paths, box, monkeypatch) -> None:
    def missing(cmd, capture=False, timeout=None):
        raise bu.DockerError("No such image")
    monkeypatch.setattr(bu, "_run", missing)
    bu.bring_up(paths, _inv(), Journal(FORWARD, "rebuilt", 1048576), lambda: None,
                component="userns-migrate")
    assert box[0] == ("platform", "system", True)


def _monitor_stop(paths, project) -> None:
    paths.project_health_state(project).parent.mkdir(parents=True, exist_ok=True)
    paths.project_health_state(project).write_text(json.dumps(
        {"status": MONITOR_STOPPED, "stopped_at": "2026-10-19T00:00:00+00:00"}))


def test_a_project_the_health_monitor_stopped_stays_down(paths, box) -> None:
    """The monitor can stop a project while the box runs on before the switch; its
    stop marker stands until `recover`, so starting it would leave a running project
    marked stopped (nothing bumps last_started_at)."""
    _monitor_stop(paths, "good")
    results = bu.bring_up(paths, _inv(), Journal(FORWARD, "rebuilt", 1048576), lambda: None,
                          component="userns-migrate")
    assert results["good"] == "left stopped by the health monitor"
    assert not [e for e in box if e[0] == "up" and e[1] == "good"]
    assert ("overlay", "good") in box and ("route", "good") not in box
    assert not paths.project_caddy_site("good").exists()  # its own page stays


def _running(monkeypatch, running: dict[str, set[str]]) -> None:
    """The containers Docker reports now: project -> the services running."""
    def containers(project):
        return [type("C", (), {"service": svc, "running": True, "oneoff": False})()
                for svc in sorted(running.get(project, ()))]
    monkeypatch.setattr(bu.docker_containers, "project_containers", containers)


def _carried_on_inv():
    return Inventory("overlay2", "", "/v", "29.9.0", projects=["good", "bad", "held"],
                     containers=[_c("good-app-1", "good"), _c("good-worker-1", "good", "worker"),
                                 _c("bad-app-1", "bad")])


def test_an_abort_starts_only_the_services_that_are_not_running_now(
        paths, box, monkeypatch) -> None:
    _running(monkeypatch, {"good": {"app"}})
    results = bu.bring_up(paths, _carried_on_inv(), Journal(FORWARD, "started", 1048576),
                          lambda: None, component="userns-rollback", prefix="abort",
                          only_stopped=True)
    assert results["good"] == "up" and ("up", "good", ("worker",), True, False) in box


def test_an_abort_leaves_a_healthy_running_project_alone(paths, box, monkeypatch) -> None:
    """Putting it behind the maintenance page and running its smoke tests could strand
    a healthy project there when a smoke test fails."""
    _running(monkeypatch, {"good": {"app", "worker"}})
    smoked = []
    monkeypatch.setattr(bu, "smoke_ok", lambda p, *a: smoked.append(p) or False)
    results = bu.bring_up(paths, _carried_on_inv(), Journal(FORWARD, "started", 1048576),
                          lambda: None, component="userns-rollback", prefix="abort",
                          only_stopped=True)
    assert results["good"] == "already running"
    assert not [e for e in box if e[0] in ("up", "route") and e[1] == "good"]
    assert "good" not in smoked and not paths.project_caddy_site("good").exists()
    assert results["bad"] == "failed: container exited"  # a stopped one is still started


def test_an_abort_never_restarts_a_monitor_stopped_project(paths, box, monkeypatch) -> None:
    _running(monkeypatch, {})
    _monitor_stop(paths, "good")
    results = bu.bring_up(paths, _carried_on_inv(), Journal(FORWARD, "started", 1048576),
                          lambda: None, component="userns-rollback", prefix="abort",
                          only_stopped=True)
    assert results["good"] == "left stopped by the health monitor"
    assert not [e for e in box if e[0] == "up" and e[1] == "good"]


def test_a_rerun_migration_does_not_restart_a_project_stopped_since_the_first_attempt(
        paths, box) -> None:
    """with_running_from carries "was running" over from the earlier inventory, and
    the monitor's stop removed the containers since: the bring-up still holds it."""
    earlier = _carried_on_inv()
    fresh = Inventory("overlay2", "", "/v", "29.9.0", projects=["good", "bad", "held"],
                      containers=[_c("bad-app-1", "bad")])
    inv = fresh.with_running_from(earlier)
    assert [c.name for c in inv.containers if c.service and c.running] \
        == ["bad-app-1", "good-app-1", "good-worker-1"]
    _monitor_stop(paths, "good")
    results = bu.bring_up(paths, inv, Journal(FORWARD, "rebuilt", 1048576), lambda: None,
                          component="userns-migrate")
    assert results["good"] == "left stopped by the health monitor"
    assert not [e for e in box if e[0] == "up" and e[1] == "good"]


@pytest.mark.parametrize("failed_key", ["restart:good", "abort:good", "project:good"])
def test_an_abort_redoes_a_project_an_earlier_bring_up_left_failed(
        paths, box, monkeypatch, failed_key) -> None:
    """After an undone switch the restart puts the project behind the page; its
    containers may run while its smoke tests failed. All services running is not
    "healthy": the full bring-up gives it its routes back."""
    _running(monkeypatch, {"good": {"app", "worker"}})
    j = Journal(FORWARD, "started", 1048576, items={failed_key: "failed: its smoke tests failed"})
    results = bu.bring_up(paths, _carried_on_inv(), j, lambda: None,
                          component="userns-rollback", prefix="abort", only_stopped=True)
    assert results["good"] == "up" and ("route", "good") in box
    assert ("up", "good", ("app", "worker"), True, False) in box
