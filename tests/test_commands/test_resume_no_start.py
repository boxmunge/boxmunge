"""`resume --no-start`: the explicit exit from a pause that only a deploy
can repair.

Each case is a state resume refuses to start, whose remedy is a deploy (which
a plain pause refuses). The refusal names `resume <p> --no-start`, then
`prod-deploy <p> --redeploy` (the inbox holds no new bundle), and that
remedy is shown to succeed. In between, the
project stays paused for everything but a deploy.
"""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from boxmunge.commands.deploy import deploy_eligible, run_deploy
from boxmunge.commands.pause_cmd import run_pause
from boxmunge.commands.resume_cmd import run_resume
from boxmunge.compose_guard import ComposeRefused
from boxmunge.lifecycle import BlockReason, is_blocked
from boxmunge.pause import (
    awaiting_deploy, is_paused, mark_pause_complete, render_maintenance_caddy_config,
    write_paused_state,
)
from boxmunge.project_registry import add_project
from boxmunge.release_txn import load_txn
from boxmunge.state import read_state
from tests.bundle_helpers import HOSTILE_COMPOSE, place_bundle
from tests.txn_helpers import docker_off, flaky_hook, hook_manifest

V1, V2 = "2026-10-16T090000000000", "2026-10-16T100000000000"
REF1, REF2 = f"myapp-{V1}", f"myapp-{V2}"
BIND_COMPOSE = "services:\n  web:\n    image: nginx\n    volumes:\n      - ./data:/data\n"
MAINTENANCE = render_maintenance_caddy_config(["myapp.example.com"])


def _paused_v1(paths, compose: str = BIND_COMPOSE) -> None:
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1, files={"compose.yml": compose})
    with docker_off():
        assert run_deploy("myapp", paths, ref=V1) == 0
    _pause(paths)


def _pause(paths) -> None:
    write_paused_state("myapp", paths, reason="maintenance")
    mark_pause_complete("myapp", paths)
    paths.project_caddy_site("myapp").write_text(MAINTENANCE)


def _resume(paths, **kw) -> int:
    with docker_off() as up, patch("boxmunge.commands.resume_cmd.run_smoke",
                                   return_value=(True, "ok")):
        rc = run_resume("myapp", paths, yes=True, skip_security_checks=True, **kw)
    _resume.up_calls = up.call_count
    return rc


def _remedy_succeeds(paths, capsys, refused_rc: int, ref: str | None = None) -> None:
    """Resume refuses naming the remedy; `--no-start` then `prod-deploy`
    (--redeploy, or --ref for a new upload) works."""
    assert _resume(paths) == refused_rc and _resume.up_calls == 0
    err = capsys.readouterr().err
    assert "`boxmunge resume myapp --no-start`, then `boxmunge prod-deploy myapp --redeploy`" in err \
        or "`boxmunge resume myapp --no-start` first" in err
    assert is_paused("myapp", paths) and not deploy_eligible("myapp", paths)
    assert _resume(paths, no_start=True) == 0 and _resume.up_calls == 0
    assert awaiting_deploy("myapp", paths)
    assert paths.project_caddy_site("myapp").read_text() == MAINTENANCE
    with docker_off() as up:
        assert run_deploy("myapp", paths, ref=ref, redeploy=ref is None) == 0
        up.assert_called()
    assert not is_paused("myapp", paths)
    assert paths.project_caddy_site("myapp").read_text() != MAINTENANCE
    assert load_txn(paths, "myapp") is None


def test_a_compose_file_edited_while_paused(paths, capsys) -> None:
    _paused_v1(paths)
    compose = paths.project_dir("myapp") / "compose.yml"
    compose.write_text(BIND_COMPOSE.replace("image: nginx", "image: nginx:1.27"))
    _remedy_succeeds(paths, capsys, refused_rc=3)
    assert "nginx:1.27" in compose.read_text()   # the edit is what was deployed


def test_a_mount_the_deploy_did_not_record(paths, capsys) -> None:
    _paused_v1(paths)
    record = paths.project_bind_record("myapp")
    doc = json.loads(record.read_text())
    doc["sources"] = {}
    record.write_text(json.dumps(doc))
    _remedy_succeeds(paths, capsys, refused_rc=3)


def test_a_missing_bind_source_record(paths, capsys) -> None:
    _paused_v1(paths)
    paths.project_bind_record("myapp").unlink()
    _remedy_succeeds(paths, capsys, refused_rc=3)
    assert paths.project_bind_record("myapp").exists()


def test_a_release_the_validator_now_rejects(paths, capsys) -> None:
    """Deployed before the rule (written in place here): a new release fixes it."""
    _paused_v1(paths, compose="services:\n  web:\n    image: nginx\n")
    (paths.project_dir("myapp") / "compose.yml").write_text(HOSTILE_COMPOSE)
    place_bundle(paths, timestamp=V2)
    _remedy_succeeds(paths, capsys, refused_rc=3, ref=V2)
    assert read_state(paths.project_deploy_state("myapp"))["current_ref"] == REF2


def test_an_image_gone_from_the_local_store(paths, capsys) -> None:
    _paused_v1(paths)
    with patch("boxmunge.docker_containers.absent_images",
               return_value=[("web", "nginx")]), \
            patch("boxmunge.commands.resume_cmd.release_restart_policies") as released:
        assert _resume(paths) == 1
    released.assert_not_called()   # given back only once a start has run
    err = capsys.readouterr().err
    assert "`boxmunge resume myapp --no-start`, then `boxmunge prod-deploy myapp --redeploy`" in err
    assert _resume(paths, no_start=True) == 0
    with docker_off():
        assert run_deploy("myapp", paths, redeploy=True) == 0
    assert not is_paused("myapp", paths)


def test_an_open_install(paths, capsys, tmp_path) -> None:
    """Paused over an install whose hook failed (an earlier boxmunge allowed
    it): `--no-start`, then the install's own rerun finishes it."""
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1)
    place_bundle(paths, timestamp=V2, files={"manifest.yml": hook_manifest(flaky_hook(tmp_path))})
    with docker_off():
        assert run_deploy("myapp", paths, ref=V1) == 0
        assert run_deploy("myapp", paths, ref=V2) == 1
    assert load_txn(paths, "myapp").phase == "hook_started"
    _pause(paths)
    assert _resume(paths) == 1
    assert "--no-start` first" in capsys.readouterr().err
    assert _resume(paths, no_start=True) == 0
    assert f"prod-deploy myapp --ref {REF2}" in capsys.readouterr().out
    with docker_off():
        assert run_deploy("myapp", paths, ref=V2) == 0
    assert not is_paused("myapp", paths) and load_txn(paths, "myapp") is None
    assert read_state(paths.project_deploy_state("myapp"))["current_ref"] == REF2


# ---- the state in between ----


def test_it_stays_paused_for_everything_but_a_deploy(paths, capsys) -> None:
    from boxmunge.commands.check import _check_one
    from boxmunge.health_checks.projects import check_lifecycle_blocked
    from boxmunge.commands.status import collect_status, display_rows
    _paused_v1(paths)
    assert _resume(paths, no_start=True) == 0
    block = is_blocked("myapp", paths)
    # Timers (health, backups, container updates, upgrade restarts) skip a
    # paused project: nothing starts it but the deploy.
    assert block is not None and block.reason is BlockReason.PAUSED
    assert "prod-deploy myapp --redeploy" in block.refuse_message
    [row] = display_rows(collect_status(paths).rows)
    assert row["status"] == "PAUSED (awaiting deploy)"
    lifecycle = check_lifecycle_blocked(paths)
    assert lifecycle.status == "warn" and "awaiting a deploy: myapp" in lifecycle.detail
    with patch("boxmunge.commands.check.update_health_state") as health:
        assert _check_one("myapp", paths, read_only=False) == 0
    health.assert_not_called()
    assert "PAUSED (awaiting deploy" in capsys.readouterr().out


def test_a_deploy_that_never_started_leaves_it_awaiting(paths, capsys) -> None:
    _paused_v1(paths)
    assert _resume(paths, no_start=True) == 0
    with docker_off() as up, \
            patch("boxmunge.commands.deploy_handover.give_release_policies") as released, \
            patch("boxmunge.compose_guard.check_start",
                  side_effect=ComposeRefused("bind source changed kind")):
        assert run_deploy("myapp", paths, redeploy=True) == 1
        up.assert_not_called()
    released.assert_not_called()   # still held: nothing started
    assert awaiting_deploy("myapp", paths)
    assert paths.project_caddy_site("myapp").read_text() == MAINTENANCE
    assert "stays paused, awaiting a deploy: nothing was started" in capsys.readouterr().err


def test_policies_are_given_back_only_after_the_up(paths) -> None:
    _paused_v1(paths)
    assert _resume(paths, no_start=True) == 0
    order: list[str] = []
    with docker_off() as up, patch("boxmunge.commands.deploy_handover.give_release_policies",
                                   side_effect=lambda *a: order.append("release")):
        up.side_effect = lambda *a, **k: order.append("up")
        assert run_deploy("myapp", paths, redeploy=True) == 0
    assert order == ["up", "release"]


def test_a_start_that_fails_part_way_keeps_the_pause(paths, capsys) -> None:
    """The up failed after starting some containers: they are stopped again
    and the policies held, so the project is paused as before (not left
    half-started behind its maintenance page, or under stale routing)."""
    from boxmunge.docker_run import DockerError
    _paused_v1(paths)
    assert _resume(paths, no_start=True) == 0
    with docker_off() as up, \
            patch("boxmunge.pause.compose_stop") as stopped, \
            patch("boxmunge.pause.hold_restart_policies") as held:
        up.side_effect = DockerError("container web exited (1)")
        assert run_deploy("myapp", paths, redeploy=True) == 1
    stopped.assert_called_once()
    held.assert_called_once()
    assert awaiting_deploy("myapp", paths)
    assert paths.project_caddy_site("myapp").read_text() == MAINTENANCE
    assert "what the failed start started was stopped again" in capsys.readouterr().err
    with docker_off():
        assert run_deploy("myapp", paths, redeploy=True) == 0
    assert not is_paused("myapp", paths)


def test_no_start_refuses_an_incomplete_pause(paths, capsys) -> None:
    _paused_v1(paths)
    write_paused_state("myapp", paths)   # not marked complete: may still be serving
    assert _resume(paths, no_start=True) == 1
    assert "pause myapp" in capsys.readouterr().err
    assert not awaiting_deploy("myapp", paths)


@pytest.mark.parametrize("args", [["myapp", "--no-start"], ["myapp", "--no-start", "--yes"]])
def test_the_deploy_shell_passes_the_flag(args) -> None:
    from boxmunge.shell import operator_only_reason, run_command
    assert operator_only_reason("resume", args) is None
    with patch("boxmunge.shell.subprocess.run") as run:
        run.return_value.returncode = 0
        run_command("resume", args)
    run.assert_called_once_with(["boxmunge-server", "resume", *args])


def test_paused_and_quarantined_by_a_finding_only_a_rebuild_fixes(
        paths, capsys, monkeypatch) -> None:
    """A KEV finding no suppression or re-scan clears: security resume
    refuses, so the way out is a deploy of a rebuilt release. `--no-start`
    hands the pause to it; its images are scanned first, and the clean
    deploy ends the pause and lifts the quarantine."""
    from boxmunge.commands import quarantine_gate
    from boxmunge.cve.quarantine import clear_quarantine_state, is_quarantined
    from tests.test_commands.cve_helpers import BALANCED, make_clearance, seed_quarantine
    _paused_v1(paths)
    seed_quarantine(paths, "myapp")
    place_bundle(paths, timestamp=V2, files={"compose.yml": BIND_COMPOSE})
    assert run_deploy("myapp", paths, ref=V2) == 1
    err = capsys.readouterr().err
    assert "paused and CVE-quarantined" in err and "resume myapp --no-start" in err
    assert _resume(paths) == 1   # resume names the same way out
    assert "resume myapp --no-start" in capsys.readouterr().err
    assert _resume(paths, no_start=True) == 0
    assert "its images are scanned first" in capsys.readouterr().out
    clearance = make_clearance("myapp", {"web": ("nginx", "sha256:x")}, before=BALANCED)
    monkeypatch.setattr("boxmunge.commands.release_config.clear_release", lambda *a: clearance)
    monkeypatch.setattr("boxmunge.commands.deploy_tree.require_unchanged", lambda *a: None)
    monkeypatch.setattr(quarantine_gate, "_verify_running",
                        lambda paths_, c, component, **kw: {"myapp-web-1": "web"})
    monkeypatch.setattr(quarantine_gate, "_release_policies",
                        lambda paths_, project, services: {"myapp-web-1": "always"})
    monkeypatch.setattr(quarantine_gate, "lift_quarantine",
                        lambda project, paths_, **kw: clear_quarantine_state(project, paths_))
    with docker_off():
        assert run_deploy("myapp", paths, ref=V2) == 0
    assert not is_paused("myapp", paths) and not is_quarantined("myapp", paths)
    assert read_state(paths.project_deploy_state("myapp"))["current_ref"] == REF2


def test_no_start_takes_an_unfinished_pause_over_an_open_install(paths, capsys, tmp_path) -> None:
    """`pause` would finish it, but an open install refuses a pause: only the
    install's deploy can end it."""
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1)
    place_bundle(paths, timestamp=V2, files={"manifest.yml": hook_manifest(flaky_hook(tmp_path))})
    with docker_off():
        assert run_deploy("myapp", paths, ref=V1) == 0
        assert run_deploy("myapp", paths, ref=V2) == 1
    write_paused_state("myapp", paths)   # never marked complete
    assert _resume(paths, no_start=True) == 0
    assert awaiting_deploy("myapp", paths)
    out = capsys.readouterr().out
    assert f"prod-deploy myapp --ref {REF2}" in out and "rollback myapp' restores" not in out
    with docker_off():
        assert run_deploy("myapp", paths, ref=V2) == 0
    assert not is_paused("myapp", paths)


def test_each_container_gets_its_new_releases_policy(paths, fake_containers, monkeypatch) -> None:
    """The pause saved V1's policies; V2 changes them both ways. Each
    container ends with V2's own policy, never one saved from V1: `always`
    added must survive a reboot, and `no` must not bring back a one-shot."""
    two = ("services:\n  web:\n    image: nginx\n    restart: {web}\n"
           "  job:\n    image: busybox\n    restart: \"{job}\"\n")
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1, files={"compose.yml": two.format(web="no", job="always")})
    with docker_off():
        assert run_deploy("myapp", paths, ref=V1) == 0
    fake_containers.run("myapp", "web", "sha256:w")
    fake_containers.run("myapp", "job", "sha256:j")
    policies = {"myapp-web-1": "no", "myapp-job-1": "always"}
    monkeypatch.setattr("boxmunge.restart_hold.project_restart_policies",
                        lambda *, project_name: dict(policies))

    def set_policy(names, policy):
        policies.update({n: policy for n in names})
    monkeypatch.setattr("boxmunge.restart_hold.set_restart_policy", set_policy)
    with patch("boxmunge.commands.pause_cmd.caddy_reload"), \
            patch("boxmunge.commands.pause_cmd.compose_stop"):
        assert run_pause("myapp", paths, yes=True) == 0
    assert policies == {"myapp-web-1": "no", "myapp-job-1": "no"}   # held
    assert _resume(paths, no_start=True) == 0
    place_bundle(paths, timestamp=V2, files={"compose.yml": two.format(web="always", job="no")})
    with docker_off():
        assert run_deploy("myapp", paths, ref=V2) == 0
    assert policies == {"myapp-web-1": "always", "myapp-job-1": "no"}


def test_plain_resume_still_starts_a_pause_awaiting_a_deploy(paths) -> None:
    """data chown's refusal for this state names `resume` for the case where
    the awaited deploy is itself refused until the chown (#144 review P3-2)."""
    _paused_v1(paths, compose="services:\n  web:\n    image: nginx\n")
    assert _resume(paths, no_start=True) == 0 and awaiting_deploy("myapp", paths)
    with patch("boxmunge.commands.resume_cmd.caddy_reload"):
        assert _resume(paths) == 0 and _resume.up_calls == 1
    assert not is_paused("myapp", paths)



def _scans_clean(paths, monkeypatch, image: str) -> None:
    """The deploy's scan of `image` finds nothing quarantine-level. The image
    id is the one the unit tier's image store reports, so the gate's check
    that the deploy starts what was scanned runs."""
    import hashlib
    from boxmunge.commands import quarantine_gate
    from boxmunge.cve.quarantine import clear_quarantine_state
    from boxmunge.paths import BoxPaths
    from tests.test_commands.cve_helpers import BALANCED, make_clearance
    scanned = "sha256:" + hashlib.sha256(image.encode()).hexdigest()
    clearance = make_clearance("myapp", {"web": (image, scanned)}, before=BALANCED)
    monkeypatch.setattr("boxmunge.commands.release_config.clear_release", lambda *a: clearance)
    monkeypatch.setattr(quarantine_gate, "_verify_running",
                        lambda paths_, c, component, **kw: {"myapp-web-1": "web"})
    monkeypatch.setattr(quarantine_gate, "_release_policies",
                        lambda paths_, project, services: {"myapp-web-1": "always"})
    monkeypatch.setattr(quarantine_gate, "lift_quarantine",
                        lambda project, paths_, **kw: clear_quarantine_state(project, paths_))
    monkeypatch.setattr(BoxPaths.__init__, "__defaults__", (paths.root,))


def _run(command: str) -> int:
    """`boxmunge <command>` as the deploy shell runs it."""
    from boxmunge import cli
    with docker_off(), patch("sys.argv", ["boxmunge", *command.split()]), \
            pytest.raises(SystemExit) as done:
        cli.main()
    return done.value.code


def _named(text: str) -> list[str]:
    import re
    return re.findall(r"`boxmunge ([^`]+)`", text)


def test_the_upgrades_way_back_for_a_paused_quarantined_project_runs(
        paths, monkeypatch) -> None:
    """An upgrade refuses to record a paused, quarantined project whose
    compose.yml changed since its deploy, and names the way back. Each
    command it names runs, in order, from that state: `security resume`
    then `resume` would not (resume runs the same start check)."""
    from boxmunge.commands.upgrade_offline import offline_exit
    from boxmunge.cve.quarantine import clear_quarantine_state, is_quarantined
    from tests.test_commands.cve_helpers import seed_quarantine
    _paused_v1(paths)
    seed_quarantine(paths, "myapp")
    compose = paths.project_dir("myapp") / "compose.yml"
    compose.write_text(BIND_COMPOSE.replace("image: nginx", "image: nginx:1.27"))
    clear_quarantine_state("myapp", paths)   # what `security resume` leaves: paused
    assert _resume(paths) == 3   # and `resume` refuses the changed file
    seed_quarantine(paths, "myapp")
    commands = _named(offline_exit(paths, "myapp"))
    assert commands == ["resume myapp --no-start", "prod-deploy myapp --redeploy"]
    _scans_clean(paths, monkeypatch, "nginx:1.27")
    for command in commands:
        assert _run(command) == 0, command
    assert not is_paused("myapp", paths) and not is_quarantined("myapp", paths)
    assert "nginx:1.27" in compose.read_text()   # the edit is what was deployed


def test_the_upgrades_way_back_for_a_quarantined_project_names_a_deploy_that_runs(
        paths, monkeypatch) -> None:
    """Not paused: `security resume` runs the start check and is refused
    while the changed file stands; the deploy it names instead runs."""
    from boxmunge.commands.quarantine_lift import restore_from_quarantine
    from boxmunge.commands.upgrade_offline import offline_exit
    from boxmunge.cve.quarantine import QuarantineError, is_quarantined
    from tests.test_commands.cve_helpers import seed_quarantine
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1, files={"compose.yml": BIND_COMPOSE})
    with docker_off():
        assert run_deploy("myapp", paths, ref=V1) == 0
    seed_quarantine(paths, "myapp")
    compose = paths.project_dir("myapp") / "compose.yml"
    compose.write_text(BIND_COMPOSE.replace("image: nginx", "image: nginx:1.27"))
    commands = _named(offline_exit(paths, "myapp"))
    assert commands == ["security resume myapp", "prod-deploy myapp --redeploy"]
    # What `security resume` runs once its re-scan is clear:
    with docker_off(), pytest.raises(QuarantineError, match="compose.yml changed"):
        restore_from_quarantine(paths, "myapp", component="security-resume")
    _scans_clean(paths, monkeypatch, "nginx:1.27")
    assert _run(commands[1]) == 0
    assert not is_quarantined("myapp", paths)


@pytest.mark.parametrize("quarantined", [False, True], ids=["paused", "quarantined"])
def test_the_upgrades_way_back_says_when_each_way_applies(paths, quarantined) -> None:
    from boxmunge.commands.upgrade_offline import offline_exit
    from boxmunge.cve.quarantine import clear_quarantine_state
    from boxmunge.pause import clear_paused_state
    from tests.test_commands.cve_helpers import seed_quarantine
    _paused_v1(paths)
    if quarantined:
        clear_paused_state("myapp", paths)
        seed_quarantine(paths, "myapp")
    text = offline_exit(paths, "myapp")
    first = "security resume myapp" if quarantined else "resume myapp"
    assert f"`boxmunge {first}` once the project's files are back as deployed" in text
    assert "to deploy them as they are" in text
    if quarantined:
        clear_quarantine_state("myapp", paths)


def test_an_unreadable_deploy_record_still_gets_a_way_back(paths) -> None:
    """A git project's redeploy names its deployed commit from the deploy
    record; one that cannot be read must not turn the upgrade's refusal
    into a traceback. Its bare deploy is accepted (no inbox)."""
    from boxmunge.commands.upgrade_offline import offline_exit
    from tests.test_commands.cve_helpers import seed_quarantine
    (paths.project_dir("gitapp") / "repo").mkdir(parents=True)
    paths.project_deploy_state("gitapp").write_text("{broken")
    seed_quarantine(paths, "gitapp")
    text = offline_exit(paths, "gitapp")
    assert "`boxmunge prod-deploy gitapp`" in text
