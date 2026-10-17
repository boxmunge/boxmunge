# SPDX-License-Identifier: Apache-2.0
"""A paused project stays stopped across a Docker restart (B-19, for pause)."""
from __future__ import annotations

import pytest

from boxmunge.commands import pause_cmd, resume_cmd
from boxmunge.commands.pause_cmd import run_pause
from boxmunge.commands.resume_cmd import run_resume
from boxmunge.docker import DockerError
from boxmunge.pause import read_paused_state
from tests.test_commands.cve_helpers import Docker, make_box


@pytest.fixture
def box(tmp_path, monkeypatch):
    paths = make_box(tmp_path)
    fake = Docker(monkeypatch)  # fakes the restart-policy primitives
    fake.policies = {"demo-web-1": "always", "demo-worker-1": "unless-stopped"}
    order: list[str] = []
    for mod in (pause_cmd, resume_cmd):
        monkeypatch.setattr(mod, "caddy_reload", lambda *a, **k: None)
    monkeypatch.setattr(pause_cmd, "compose_stop", lambda *a, **k: order.append("stop"))

    def up(*a, **k):
        order.append(f"up with web={fake.policies['demo-web-1']}")

    monkeypatch.setattr("boxmunge.compose_guard.compose_up", up)
    monkeypatch.setattr(resume_cmd, "compose_pull", lambda *a, **k: None)
    monkeypatch.setattr(resume_cmd, "prepare_caddy_config", lambda *a, **k: None)
    monkeypatch.setattr(resume_cmd, "prepare_compose_override", lambda *a, **k: None)
    monkeypatch.setattr(resume_cmd, "run_smoke", lambda *a, **k: (True, "ok"))
    fake.order = order
    return paths, fake


def test_pause_holds_restart_policies_and_saves_originals(box):
    paths, fake = box
    assert run_pause("demo", paths, yes=True) == 0
    assert fake.policies == {"demo-web-1": "no", "demo-worker-1": "no"}
    assert read_paused_state("demo", paths)["restart_policies"] == {
        "demo-web-1": "always", "demo-worker-1": "unless-stopped",
    }


def test_resume_gives_the_policies_back_before_starting(box):
    paths, fake = box
    run_pause("demo", paths, yes=True)
    assert run_resume("demo", paths, yes=True) == 0
    assert fake.policies == {"demo-web-1": "always", "demo-worker-1": "unless-stopped"}
    assert fake.order == ["stop", "up with web=always"]


def test_pause_fails_loudly_when_the_hold_fails(box, monkeypatch, capsys):
    paths, _ = box

    def boom(names, policy):
        raise DockerError("daemon not responding")

    monkeypatch.setattr("boxmunge.restart_hold.set_restart_policy", boom)
    assert run_pause("demo", paths, yes=True) == 1
    assert "restart policies could not be disabled" in capsys.readouterr().err


def test_quarantine_lifted_while_paused_keeps_the_hold_until_resume(box):
    """pause → quarantine → security resume (paused) → resume."""
    from boxmunge.cve import quarantine as q
    from tests.test_commands.cve_helpers import seed_quarantine

    paths, fake = box
    run_pause("demo", paths, yes=True)
    seed_quarantine(paths, action_complete=False)
    q.reassert_quarantine("demo", paths, project_dir=paths.project_dir("demo"),
                          hosts=["demo.example.com"], compose_files=["compose.yml"])
    q.lift_quarantine("demo", paths, project_caddy_site_content=None, compose_files=[])
    assert fake.policies["demo-web-1"] == "no"
    assert read_paused_state("demo", paths)["restart_policies"]["demo-web-1"] == "always"
    run_resume("demo", paths, yes=True)
    assert fake.policies == {"demo-web-1": "always", "demo-worker-1": "unless-stopped"}


def test_originals_prefer_a_real_policy_over_a_held_no():
    from boxmunge.restart_hold import originals
    assert originals({"a": "no", "b": "always"}, {"a": "always", "b": "no", "c": "no"}) == {
        "a": "always", "b": "always", "c": "no",
    }


def test_resume_holds_back_a_pulled_image_whose_user_changed(box, monkeypatch, capsys):
    """Resume pulls: a service running as its image's user resumes on the
    image it ran before when the new one's USER moved, and the next deploy
    pulls it again (user_drift)."""
    from boxmunge import user_drift
    from boxmunge.docker_containers import ImageFacts, LocalImage
    from boxmunge.run_as import ServiceUser, write_users
    paths, fake = box
    run_pause("demo", paths, yes=True)
    services = resume_cmd._services_to_pull("demo", paths)
    svc, ref = next(iter(services.items()))
    write_users(paths, "demo", {svc: ServiceUser(None, "manifest", "")})
    tags = {ref: "sha256:" + "0" * 64}
    monkeypatch.setattr("boxmunge.docker_containers.local_image",
                        lambda r: LocalImage(tags[r], ()) if r in tags else None)
    monkeypatch.setattr(resume_cmd, "compose_pull",
                        lambda *a, **k: tags.__setitem__(ref, "sha256:" + "1" * 64))
    monkeypatch.setattr(user_drift, "tag_image", lambda src, r: tags.__setitem__(r, src))
    monkeypatch.setattr(user_drift, "notify", lambda *a, **k: True)
    monkeypatch.setattr("boxmunge.docker_containers.image_facts",
                        lambda r: ImageFacts(tags[r], "nobody", ()))
    assert run_resume("demo", paths, yes=True) == 0
    assert tags[ref] == "sha256:" + "0" * 64 and user_drift.held_back(paths, "demo") == {svc}
    assert "resumes on its previous image" in capsys.readouterr().out
