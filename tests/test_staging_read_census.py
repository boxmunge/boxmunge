"""During a stage, production commands read only production's files
(spec 'What each command reads'). The slot is poisoned: a different
manifest (smoke, dump_command, an extra service), compose file, .env and
scripts. Allowed slot reads: the meta (status summaries) and the staged
compose.yml (DataDirs.staged); deploy and rollback also resolve staging's
model for the D8 isolation proof."""
from __future__ import annotations

import builtins
import os
import subprocess
import sys
import tarfile
from contextlib import ExitStack, contextmanager
from unittest.mock import patch

import pytest

from boxmunge import docker_run
from tests.bundle_helpers import manifest_text, place_bundle
from tests.stage_helpers import V3, prod_and_stage, staging_docker_off

SLOT = "/.releases/staged/"
ALWAYS = ("/.releases/staged/meta.json", "/.releases/staged/release/compose.yml")
D8 = ALWAYS + ("/.releases/staged/compose.staging-base.yml",
               "/.releases/staged/compose.boxmunge-staging.yml",
               "/.releases/staged/release/.env")

POISON = {
    "manifest.yml": manifest_text(backup="postgres").replace("dump.sh", "POISON-dump.sh")
    .replace("    port: 8080\n", "    port: 8080\n    smoke: boxmunge-scripts/poison.sh\n"),
    "compose.yml": "services:\n  web:\n    image: nginx\n  poison:\n    image: busybox\n",
    ".env": "POISON=1\n",
    "boxmunge-scripts/poison.sh": "exit 1\n",
}


@contextmanager
def reads():
    """Every file opened (builtins, io, os and tarfile's own alias) and every
    docker argument and working directory, at every docker_run.run binding;
    a process spawned past them is refused and noted."""
    seen: list[str] = []
    real_open, real_os_open = builtins.open, os.open

    def note(path):
        try:
            seen.append(os.fsdecode(path))
        except TypeError:
            pass

    def b_open(file, *a, **k):
        note(file)
        return real_open(file, *a, **k)

    def o_open(path, *a, **k):
        note(path)
        return real_os_open(path, *a, **k)

    def docker(cmd, cwd=None, **k):
        for arg in [*cmd, cwd or ""]:
            note(arg)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    def spawn(cmd, *a, cwd=None, **k):
        for arg in [*cmd, cwd or ""]:
            note(arg)
        raise OSError("the read census spawns no process")

    seams = [patch.object(mod, "_run", docker) for name, mod in list(sys.modules.items())
             if name.startswith("boxmunge") and getattr(mod, "_run", None) is docker_run.run]
    with patch("builtins.open", b_open), patch("io.open", b_open), patch("os.open", o_open), \
            patch("tarfile.bltn_open", b_open), patch("subprocess.Popen", spawn), \
            ExitStack() as stack:
        for seam in seams:
            stack.enter_context(seam)
        yield seen


def _slot_reads(seen: list[str], allowed: tuple[str, ...]) -> list[str]:
    return [s for s in seen if SLOT in s and not s.endswith(allowed)]


@pytest.fixture
def poisoned(paths):
    prod_and_stage(paths, prod_files={"manifest.yml": manifest_text(backup="postgres")},
                   staged_files=POISON)
    paths.backup_key.parent.mkdir(parents=True, exist_ok=True)
    paths.backup_key.write_text("key")
    return paths


def _backup(paths):
    from boxmunge.commands.backup_cmd import backup_locked
    with patch("boxmunge.commands.backup_cmd._run_backup_inner", return_value=0) as inner:
        assert backup_locked("myapp", paths) == 0
    assert "POISON" not in inner.call_args.args[2]


def _restart(paths):
    from boxmunge.commands.upgrade_steps import regenerate_configs, restart_projects
    with staging_docker_off():
        regenerate_configs(paths)
        assert restart_projects(paths, refused=()).succeeded == ["myapp"]


def _pause_resume(paths):
    from boxmunge.commands.pause_cmd import pause_locked
    from boxmunge.commands.resume_cmd import resume_locked
    with staging_docker_off(), patch("boxmunge.commands.pause_cmd.compose_stop"), \
            patch("boxmunge.commands.pause_cmd.caddy_reload"), \
            patch("boxmunge.commands.resume_cmd.caddy_reload"), \
            patch("boxmunge.commands.resume_cmd.compose_pull"):
        assert pause_locked("myapp", paths, reason=None) == 0
        assert resume_locked("myapp", paths, True)[0] == 0


def _redeploy(paths):
    from boxmunge.commands.deploy import run_deploy
    with staging_docker_off(), \
            patch("boxmunge.commands.backup_cmd._run_backup_inner", return_value=0) as inner:
        assert run_deploy("myapp", paths) == 0
    assert "POISON" not in str(inner.call_args.args[2])


def _stash(paths):
    from boxmunge.stash import create_stash
    with tarfile.open(create_stash(paths)) as tar:
        stashed = tar.extractfile("projects/myapp/manifest.yml").read().decode()
        assert not any(".releases" in name for name in tar.getnames())
    assert "POISON" not in stashed


def _tick(paths):
    from boxmunge.commands.check import _check_one
    assert _check_one("myapp", paths, read_only=False) == 0


def _restore_plan(paths):
    from boxmunge.commands.restore import restore_locked
    (paths.project_backups("myapp")).mkdir(parents=True, exist_ok=True)
    (paths.project_backups("myapp") / "myapp-x.tar.gz.age").write_text("s")
    with patch("boxmunge.commands.restore._run_restore_inner", return_value=0):
        assert restore_locked("myapp", paths, snapshot="myapp-x.tar.gz.age") == 0


@pytest.mark.parametrize("command", [_backup, _restart, _pause_resume, _redeploy, _stash,
                                     _restore_plan, _tick])
def test_production_command_reads_no_staged_file(poisoned, command) -> None:
    with reads() as seen:
        command(poisoned)
    assert _slot_reads(seen, ALWAYS) == []


def test_the_spy_sees_a_staged_read(poisoned) -> None:
    """Guards the census itself: a real read of the poisoned slot is caught."""
    from boxmunge.manifest import load_manifest
    slot = poisoned.project_releases("myapp") / "staged" / "release"
    with reads() as seen:
        load_manifest(slot / "manifest.yml")
        (slot / ".env").read_text()
        with tarfile.open(poisoned.root / "t.tar", "w") as tar:
            tar.add(slot / "boxmunge-scripts" / "poison.sh", arcname="p")
        with pytest.raises(OSError):  # a spawn past the docker seams
            subprocess.run(["docker", "compose", "logs"], cwd=slot)
    caught = _slot_reads(seen, ALWAYS)
    for read in ("release/manifest.yml", "release/.env", "release/boxmunge-scripts/poison.sh"):
        assert any(s.endswith(read) for s in caught), read
    assert any(s.endswith("/staged/release") for s in caught)  # the spawn's cwd


def test_prod_deploy_reads_the_slot_only_for_the_isolation_proof(poisoned) -> None:
    from boxmunge.commands.deploy import run_deploy
    place_bundle(poisoned, timestamp=V3)
    with staging_docker_off(), reads() as seen, \
            patch("boxmunge.commands.backup_cmd._run_backup_inner", return_value=0):
        assert run_deploy("myapp", poisoned, ref=V3) == 0
    assert _slot_reads(seen, D8) == []
