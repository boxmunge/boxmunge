"""Quiesce order; bring-up keeps failed projects on the maintenance page."""
from __future__ import annotations

import pytest

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
    monkeypatch.setattr(bu, "is_blocked", lambda p, paths: held if p == "held" else None)

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
