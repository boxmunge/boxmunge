"""During a stage, production commands read only production's files
(spec 'What each command reads', production side: one case per row). The
slot is poisoned: a different manifest (smoke, dump_command, an extra
service), compose file, .env and scripts. Allowed slot reads (Resolved
ambiguity 8): the meta and the staged compose.yml, opened as files; deploy
and rollback also resolve staging's model for the D8 isolation proof. Any
slot path in a production docker argument or working directory is a
violation."""
from __future__ import annotations

import subprocess
import tarfile
from dataclasses import dataclass, field
from unittest.mock import patch

import pytest

from boxmunge.commands.smoke_result import SmokeResult
from tests.bundle_helpers import manifest_text, place_bundle
from tests.read_census_spy import Seen, reads
from tests.stage_helpers import V3, prod_and_stage, staging_docker_off

SMOKE = "    port: 8080\n    smoke: boxmunge-scripts/{}\n"
PROD = {"manifest.yml": manifest_text(backup="postgres").replace(
    "    port: 8080\n", SMOKE.format("smoke.sh")), "boxmunge-scripts/smoke.sh": "exit 0\n"}
POISON = {
    "manifest.yml": manifest_text(backup="postgres").replace("dump.sh", "POISON-dump.sh")
    .replace("    port: 8080\n", SMOKE.format("poison.sh")),
    "compose.yml": "services:\n  web:\n    image: nginx\n  poison:\n    image: busybox\n",
    ".env": "POISON=1\n",
    "boxmunge-scripts/poison.sh": "exit 1\n",
}


@dataclass
class Box:
    """The poisoned box; ``smoke`` is what production's smoke returns, and
    ``ran`` every smoke script run in a container."""
    paths: object
    smoke: str = "ok"
    ran: list[str] = field(default_factory=list)


@pytest.fixture
def box(paths, fake_containers, monkeypatch):
    the_box = Box(paths)

    def smoke_one(container, script, service):
        the_box.ran.append(script)
        return SmokeResult(status=the_box.smoke, message=f"smoke {the_box.smoke}")

    monkeypatch.setattr("boxmunge.commands.check._smoke_one", smoke_one)
    fake_containers.run("myapp", "web", "sha256:1")
    prod_and_stage(paths, prod_files=PROD, staged_files=POISON)
    paths.backup_key.parent.mkdir(parents=True, exist_ok=True)
    paths.backup_key.write_text("key")
    the_box.ran.clear()
    return the_box


def _dumped(seen: Seen) -> None:
    """The backup's dump ran (refused at the spawn) with production's command."""
    assert "dump.sh" in seen.docker and "POISON-dump.sh" not in seen.docker


def _backup(box, seen):
    from boxmunge.commands.backup_cmd import backup_locked
    assert backup_locked("myapp", box.paths) == 1   # the census refuses the dump's exec
    _dumped(seen)


def _restore(box, seen):
    from boxmunge.commands.restore import restore_locked
    paths = box.paths
    paths.project_backups("myapp").mkdir(parents=True, exist_ok=True)
    (paths.project_backups("myapp") / "myapp-x.tar.gz.age").write_text("s")
    # The decrypt runs in the boxmunge-system container (not in the census);
    # the restore's inputs are what production's manifest names.
    with patch("boxmunge.commands.restore._run_restore_inner", return_value=0) as inner:
        assert restore_locked("myapp", paths, snapshot="myapp-x.tar.gz.age") == 0
    assert "POISON" not in str(inner.call_args)


def _redeploy(box, seen):
    from boxmunge.commands.deploy import run_deploy
    with staging_docker_off():
        assert run_deploy("myapp", box.paths) == 0     # its pre-deploy backup fails: a WARN
    _dumped(seen)


def _rollback(box, seen):
    from boxmunge.commands.deploy import run_deploy
    from boxmunge.commands.rollback import rollback_locked
    place_bundle(box.paths, timestamp=V3, files=PROD)
    snapshot = box.paths.project_backups("myapp") / "myapp-p1.tar.gz.age"

    def backup(project, paths, kind=None, manifest=None):
        assert "POISON" not in str(manifest)
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_text("snapshot")
        return 0

    with staging_docker_off(), patch("boxmunge.commands.backup_cmd.backup_locked", backup), \
            patch("boxmunge.commands.rollback.restore_locked", return_value=0) as restore:
        assert run_deploy("myapp", box.paths, ref=V3) == 0
        assert rollback_locked("myapp", box.paths) == 0
    assert restore.call_args.kwargs["snapshot"] == snapshot.name


def _pause_resume(box, seen):
    from boxmunge.commands.pause_cmd import pause_locked
    from boxmunge.commands.resume_cmd import resume_locked
    with staging_docker_off(), patch("boxmunge.commands.pause_cmd.caddy_reload"), \
            patch("boxmunge.commands.resume_cmd.caddy_reload"):
        assert pause_locked("myapp", box.paths, reason=None) == 0
        assert resume_locked("myapp", box.paths, True)[0] == 0
    assert "stop" in seen.docker


def _recover(box, seen):
    from boxmunge.commands.recover_cmd import recover_locked
    from boxmunge.state import write_state
    write_state(box.paths.project_health_state("myapp"), {"status": "critical_stopped"})
    with staging_docker_off(), patch("boxmunge.commands.recover_cmd.caddy_reload"):
        assert recover_locked("myapp", box.paths) == 0
    assert box.ran


def _container_update(box, seen):
    from boxmunge.commands.container_update_cmd import run_container_update
    box.paths.config_file.write_text("hostname: box.example.com\nadmin_email: ops@example.com\n")
    with staging_docker_off():
        run_container_update(box.paths, only="myapp", dry_run=True)
    assert "pull" in seen.docker


def _scan_and_quarantine(box, seen, monkeypatch):
    from boxmunge.commands import security_scan_core
    from boxmunge.cve.kev import load_kev
    from boxmunge.lifecycle import is_quarantined
    from tests.test_commands.cve_helpers import CRIT, scan_result
    monkeypatch.setattr(security_scan_core, "scan_image",
                        lambda ref, timeout: scan_result(ref, [CRIT]))
    with staging_docker_off(), patch("boxmunge.cve.quarantine.caddy_reload"):
        security_scan_core.scan_one_project_locked(
            box.paths, "myapp", in_grace=False, kev=load_kev(box.paths))
    assert is_quarantined("myapp", box.paths)
    assert "stop" in seen.docker


def _security_resume(box, seen, monkeypatch):
    from boxmunge.commands import security_resume, security_scan_core
    from tests.test_commands.cve_helpers import scan_result, seed_quarantine
    seed_quarantine(box.paths, "myapp")
    monkeypatch.setattr(security_scan_core, "scan_image", lambda ref, timeout: scan_result(ref))
    with staging_docker_off(), patch("boxmunge.cve.quarantine.caddy_reload"):
        assert security_resume.security_resume_locked(box.paths, "myapp") == 0
    assert box.ran


def _tick(box, seen):
    from boxmunge.commands.check import _check_one
    assert _check_one("myapp", box.paths, read_only=False) == 0
    assert box.ran


def _tick_critical(box, seen):
    from boxmunge.commands.check import _check_one
    box.smoke = "critical"
    with patch("boxmunge.commands.health_state.notify", return_value=True):
        assert _check_one("myapp", box.paths, read_only=False) == 2
    assert "down" in seen.docker   # the critical action, from production's files


def _logs_log(box, seen):
    from boxmunge.commands.log_cmd import run_log
    from boxmunge.commands.logs import cmd_logs
    with patch("boxmunge.commands.logs.BoxPaths", return_value=box.paths):
        cmd_logs(["myapp"])
    run_log(box.paths, project="myapp", containers=True)
    assert "logs" in seen.docker


def _status_tui_api(box, seen):
    from boxmunge.api.actions.project import _project_get
    from boxmunge.commands.status import run_status
    from boxmunge.tui.data import (
        load_all_project_status, load_project_backups, load_project_services,
    )

    class Ctx:
        paths = box.paths

    assert run_status(box.paths) == 0 and run_status(box.paths, as_json=True) == 0
    load_all_project_status(box.paths)
    assert load_project_services(box.paths, "myapp")
    load_project_backups(box.paths, "myapp")
    assert _project_get({"project": "myapp"}, Ctx())["staging"]["active"]


def _upgrade_migrate_restart(box, seen):
    from boxmunge.commands.upgrade_steps import restart_projects
    from boxmunge.upgrade_exclusions import apply_projects
    with staging_docker_off():
        _, regen, excluded = apply_projects(box.paths)
        assert not excluded.names() and not regen.refused
        assert restart_projects(box.paths, refused=(),
                                excluded=excluded.names()).succeeded == ["myapp"]


def _stash(box, seen):
    from boxmunge.stash import create_stash
    with tarfile.open(create_stash(box.paths)) as tar:
        stashed = tar.extractfile("projects/myapp/manifest.yml").read().decode()
        assert not any(".releases" in name for name in tar.getnames())
    assert "POISON" not in stashed


def _validate_diff(box, seen):
    from boxmunge.commands.diff_cmd import run_diff
    from boxmunge.commands.validate import run_validate
    assert run_validate("myapp", box.paths) == 0
    place_bundle(box.paths, timestamp=V3, files=PROD)
    assert run_diff("myapp", box.paths) == 0


PRODUCTION = [_backup, _restore, _redeploy, _pause_resume, _recover, _container_update,
              _scan_and_quarantine, _security_resume, _tick, _tick_critical, _logs_log,
              _status_tui_api, _upgrade_migrate_restart, _stash, _validate_diff]
ISOLATION_PROOF = [_rollback]   # deploy and rollback: D8


def _run(command, box, seen, monkeypatch):
    if "monkeypatch" in command.__code__.co_varnames[:command.__code__.co_argcount]:
        command(box, seen, monkeypatch)
    else:
        command(box, seen)


@pytest.mark.parametrize("command", PRODUCTION + ISOLATION_PROOF, ids=lambda c: c.__name__[1:])
def test_production_command_reads_no_staged_file(box, command, monkeypatch) -> None:
    with reads() as seen:
        _run(command, box, seen, monkeypatch)
    assert seen.violations(d8=command in ISOLATION_PROOF) == []
    assert all(script.endswith("/smoke.sh") for script in box.ran), box.ran


def test_prod_deploy_reads_the_slot_only_for_the_isolation_proof(box) -> None:
    from boxmunge.commands.deploy import run_deploy
    place_bundle(box.paths, timestamp=V3, files=PROD)
    with staging_docker_off(), reads() as seen:
        assert run_deploy("myapp", box.paths, ref=V3) == 0
    assert seen.staging_models, "the D8 proof resolved no staging model"
    assert seen.violations(d8=True) == []
    assert seen.violations() != []   # the same reads outside a D8 command are violations


def test_the_spy_sees_a_staged_read(box) -> None:
    """Guards the census itself: each kind of slot read is caught."""
    from boxmunge import docker
    from boxmunge.manifest import load_manifest
    slot = box.paths.project_releases("myapp") / "staged" / "release"
    with reads() as seen:
        load_manifest(slot / "manifest.yml")
        (slot / ".env").read_text()
        with tarfile.open(box.paths.root / "t.tar", "w") as tar:
            tar.add(slot / "boxmunge-scripts" / "poison.sh", arcname="p")
        (slot / "compose.yml").read_text()                      # allowed as a file
        docker.compose_ps(slot, [str(slot / "compose.yml")], project_name="myapp")
        with pytest.raises(OSError):  # a spawn past the docker seams
            subprocess.run(["docker", "compose", "logs"], cwd=slot)
    caught = seen.violations()
    for read in ("open", "release/manifest.yml"), ("open", "release/.env"), \
            ("open", "boxmunge-scripts/poison.sh"):
        assert any(v.startswith(read[0]) and v.endswith(read[1]) for v in caught), read
    # The allow-list is for opened files only: the same compose.yml as a
    # docker argument is a violation, and so is a slot working directory.
    assert not any(v.startswith("open") and v.endswith("release/compose.yml") for v in caught)
    assert any(v.startswith("docker") and v.endswith("release/compose.yml") for v in caught)
    assert sum(v.startswith("docker") and v.endswith("/staged/release") for v in caught) == 2
