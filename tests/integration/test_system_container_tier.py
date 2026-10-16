"""Backup, restore, test-restore, backup-sync and self-test through the REAL
boxmunge-system container.

The container is built from system/Dockerfile and started from
system/compose.yml (see ``real_system_container`` in conftest.py), mounted on
this session's temporary boxmunge root and running as the uid that owns its
projects/ directory, exactly as install.sh starts it on a server. There is no
host fallback for age or rclone, and a tripwire fails the test if:

- any age/rclone invocation is handed an absolute path outside /projects or
  /config, or an input/output whose host-side counterpart is missing; or
- anything runs age, age-keygen or rclone on the host.

This is the tier that would have caught v0.9.16 (restore and test-restore
decrypted into /tmp, which is not mounted into the container; every test took
the silent host fallback instead).

Docker Desktop on macOS maps bind-mount ownership to the container user, which
hides uid and file-ownership bugs (audit C-12). CI on Linux is the
authoritative run of this tier.
"""

import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

import pytest

import boxmunge.system_container as sc
from boxmunge.backup import BackupError, BackupKind, decrypt_file, encrypt_file
from boxmunge.commands.backup_cmd import list_snapshots, run_backup, run_backup_sync
from boxmunge.commands.restore import run_restore
from boxmunge.commands.test_restore_cmd import run_test_restore
from boxmunge.paths import BoxPaths
from tests.deploy_helpers import mark_deployed

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("system_container")]

# The system image's own base, so it is already present once the image built.
_ALPINE = "alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d"
_HOST_TOOLS = {"age", "age-keygen", "rclone"}
_FILTER_FLAGS = {"--include"}  # their values are rclone patterns, not paths


def _host_path(paths: BoxPaths, container_path: str) -> Path:
    for m in sc.system_mounts(paths):
        if container_path == m.container:
            return m.host
        if m.directory and container_path.startswith(m.container + "/"):
            return m.host / container_path.removeprefix(m.container + "/")
    raise AssertionError(f"tripwire: {container_path} is outside /projects and /config")


@pytest.fixture
def tripwire(int_paths: BoxPaths, monkeypatch):
    """Guard every system-container exec and forbid host age/rclone."""
    seen: list[list[str]] = []
    real_exec = sc.system_exec
    real_run = subprocess.run

    def guarded_exec(cmd, timeout=600, name=sc.CONTAINER_NAME):
        for i, arg in enumerate(cmd[1:], start=1):
            if not arg.startswith("/") or cmd[i - 1] in _FILTER_FLAGS:
                continue
            if not (arg == "/projects" or arg.startswith(("/projects/", "/config/"))):
                raise AssertionError(
                    f"tripwire: {cmd[0]} was handed {arg}, outside /projects and /config")
            host = _host_path(int_paths, arg)
            must_exist = host.parent if cmd[i - 1] == "-o" else host
            if not must_exist.exists():
                raise AssertionError(f"tripwire: {arg} maps to missing host path {must_exist}")
        seen.append(list(cmd))
        return real_exec(cmd, timeout=timeout, name=name)

    def no_host_tools(cmd, *args, **kwargs):
        if isinstance(cmd, (list, tuple)) and cmd and Path(str(cmd[0])).name in _HOST_TOOLS:
            raise AssertionError(f"tripwire: host {cmd[0]} invoked: {cmd}")
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(sc, "system_exec", guarded_exec)
    monkeypatch.setattr(subprocess, "run", no_host_tools)
    return seen


MANIFEST = """\
schema_version: 3
id: 01SYSTEMTIER0000000000000
project: {name}
source: bundle
hosts:
  - {name}.localhost
services:
  app:
    port: 8080
    routes:
      - path: /
    writable:
      external: true
backup:
  type: custom
  service: app
  dump_command: "tar -C /data -cf - ."
  restore_command: "tar -C /data -xf -"
  retention: 3
"""

COMPOSE = f"""\
services:
  app:
    image: {_ALPINE}
    command: ["sleep", "infinity"]
    init: true
    volumes:
      - appdata:/data
volumes:
  appdata: {{}}
"""


def _exec(project_dir: Path, name: str, script: str) -> str:
    return subprocess.run(
        ["docker", "compose", "-p", name, "-f", "compose.yml",
         "exec", "-T", "app", "sh", "-c", script],
        cwd=project_dir, check=True, capture_output=True, text=True, timeout=60,
    ).stdout


@pytest.fixture
def tiny_project(int_paths: BoxPaths, request):
    """A one-service project whose backup is a tar of a named volume.

    Parametrise indirectly with the project name (default: a unique name).
    """
    name = getattr(request, "param", None) or f"sct-{uuid.uuid4().hex[:8]}"
    project_dir = int_paths.project_dir(name)
    if project_dir.exists():
        shutil.rmtree(project_dir)
    project_dir.mkdir()
    (project_dir / "manifest.yml").write_text(MANIFEST.format(name=name))
    (project_dir / "compose.yml").write_text(COMPOSE)
    mark_deployed(int_paths, name)
    try:
        subprocess.run(["docker", "compose", "-p", name, "-f", "compose.yml", "up", "-d"],
                       cwd=project_dir, check=True, capture_output=True, timeout=180)
        yield name, project_dir
    finally:
        subprocess.run(["docker", "compose", "-p", name, "-f", "compose.yml",
                        "down", "-v", "--remove-orphans"],
                       cwd=project_dir, check=False, capture_output=True, timeout=120)
        shutil.rmtree(project_dir, ignore_errors=True)


class TestRoundTrip:
    @pytest.mark.parametrize("tiny_project", [None, "config"], indirect=True,
                             ids=["unique-name", "project-named-config"])
    def test_backup_test_restore_restore(self, int_paths, tiny_project, tripwire) -> None:
        """`config` is a valid project name that the old substring translation
        sent to the read-only key mount (C-11)."""
        name, project_dir = tiny_project
        _exec(project_dir, name, "echo before > /data/state")

        assert run_backup(name, int_paths) == 0
        [snapshot] = list_snapshots(int_paths, name)
        assert snapshot.name.endswith("-manual.tar.gz.age")

        assert run_test_restore(name, int_paths) == 0

        _exec(project_dir, name, "echo after > /data/state")
        assert run_restore(name, int_paths, snapshot=snapshot.name, yes=True) == 0
        assert _exec(project_dir, name, "cat /data/state").strip() == "before"

        tools = {cmd[0] for cmd in tripwire}
        assert tools == {"age"}
        assert not [p for p in int_paths.project_backups(name).iterdir()
                    if p.name.startswith(".")], "temp files left behind"

    def test_nightly_retention_ignores_other_kinds(self, int_paths, tiny_project, tripwire) -> None:
        name, _ = tiny_project
        for kind in (BackupKind.PREDEPLOY, BackupKind.NIGHTLY):
            assert run_backup(name, int_paths, kind=kind) == 0
        kinds = sorted(p.name.rsplit("-", 1)[1] for p in list_snapshots(int_paths, name))
        assert kinds == ["nightly.tar.gz.age", "predeploy.tar.gz.age"]


class TestV0916Regression:
    """v0.9.16: restore and test-restore decrypted into
    ``tempfile.TemporaryDirectory()`` (/tmp), which the container cannot see.
    The suite passed because age silently ran on the host instead."""

    def _snapshot(self, int_paths: BoxPaths) -> Path:
        bdir = int_paths.project_backups(f"v0916-{uuid.uuid4().hex[:6]}")
        bdir.mkdir(parents=True)
        plain = bdir / ".dump-v0916.tar.gz"
        plain.write_bytes(b"snapshot payload")
        snapshot = bdir / "snap.tar.gz.age"
        encrypt_file(plain, snapshot, int_paths)
        plain.unlink()
        return snapshot

    def test_pre_fix_decrypt_into_tmp_is_caught(self, int_paths, tripwire) -> None:
        snapshot = self._snapshot(int_paths)
        execs_before = len(tripwire)
        # The pre-fix code path, verbatim: decrypt into a /tmp temp dir.
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(BackupError, match="outside the system container's mounts"):
                decrypt_file(snapshot, Path(tmpdir) / "test-restore.tar.gz", int_paths)
            # Handed to the container untranslated, the tripwire stops it.
            with pytest.raises(AssertionError, match="tripwire"):
                sc.system_exec(["age", "--decrypt", "-i", "/config/backup.key",
                                "-o", f"{tmpdir}/out", "/projects/x.tar.gz.age"])
        assert len(tripwire) == execs_before, "age must not run for an unmounted path"

    def test_missing_container_fails_instead_of_using_host_age(
        self, int_paths, tripwire, monkeypatch, capsys,
    ) -> None:
        snapshot = self._snapshot(int_paths)
        project = snapshot.parent.parent.name
        snapshot.rename(snapshot.with_name(f"{project}-2026-01-01T000000-manual.tar.gz.age"))
        monkeypatch.setattr(sc, "CONTAINER_NAME", f"absent-{uuid.uuid4().hex[:8]}")
        assert run_test_restore(project, int_paths) == 1
        assert "does not exist" in capsys.readouterr().out


class TestBackupSync:
    """backup-sync resolves a named remote from the mounted rclone config and
    copies; local deletions never propagate (C-10, D-08)."""

    def _remote_files(self, remote_dir: str) -> set[str]:
        out = subprocess.run(
            ["docker", "exec", sc.CONTAINER_NAME, "find", remote_dir, "-type", "f"],
            capture_output=True, text=True, check=True, timeout=30,
        ).stdout
        return {line.removeprefix(remote_dir + "/") for line in out.split()}

    def test_copy_to_named_remote_keeps_deleted_snapshots(self, int_paths, tripwire) -> None:
        name = f"sync-{uuid.uuid4().hex[:6]}"
        bdir = int_paths.project_backups(name)
        bdir.mkdir(parents=True)
        (int_paths.project_dir(name) / "manifest.yml").write_text(MANIFEST.format(name=name))
        snaps = [bdir / f"{name}-2026-01-0{d}T020000-nightly.tar.gz.age" for d in (1, 2)]
        for s in snaps:
            s.write_bytes(b"ciphertext")
        (bdir / ".encrypt-x.tmp").write_bytes(b"partial")
        (int_paths.project_dir(name) / "data").mkdir()
        (int_paths.project_dir(name) / "data" / "stray.tar.gz.age").write_bytes(b"x")

        remote_dir = f"/tmp/offsite-{name}"
        int_paths.rclone_config.write_text("[offsite]\ntype = local\n")
        original = int_paths.config_file.read_text()
        int_paths.config_file.write_text(original + f"backup_remote: offsite:{remote_dir}\n")
        try:
            assert run_backup_sync(int_paths) == 0
            expected = {f"{name}/backups/{s.name}" for s in snaps}
            assert {f for f in self._remote_files(remote_dir) if f.startswith(name)} == expected

            snaps[0].unlink()  # a local prune
            assert run_backup_sync(int_paths) == 0
            assert expected <= self._remote_files(remote_dir)
        finally:
            int_paths.config_file.write_text(original)
            int_paths.rclone_config.write_text("")
            shutil.rmtree(int_paths.project_dir(name))
        assert {cmd[0] for cmd in tripwire} == {"rclone"}


class TestSelfTest:
    def test_self_test_round_trip(self, int_paths, tripwire, monkeypatch) -> None:
        """The real self-test (canary deploy, backup, wipe, restore) through the
        container. Name and port are made unique so a real canary is never
        touched."""
        from boxmunge.commands import self_test_cmd
        from tests.integration.conftest import _random_port
        project = f"canary-it-{uuid.uuid4().hex[:6]}"
        monkeypatch.setattr(self_test_cmd, "CANARY_PROJECT", project)
        monkeypatch.setattr(self_test_cmd, "CANARY_PORT", _random_port())
        try:
            assert self_test_cmd.run_self_test(int_paths) == 0
        finally:
            # self-test tears down its containers; drop the image it built too.
            subprocess.run(["docker", "rmi", "-f", f"{project}-web"],
                           capture_output=True, check=False, timeout=60)
        assert {cmd[0] for cmd in tripwire} == {"age"}
