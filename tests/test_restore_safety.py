"""restore verifies before it stops production, and always restarts it (audit C-09).

Regression for the auditor's probe: a db start that timed out, or a
PermissionError on the root-owned backups/ dir, escaped as a traceback with
production still down; a snapshot that did not decrypt was only discovered
after production had been stopped.

age runs through a fake that maps the system container's /projects paths
back to the host, so temp files must live under the project directory.
"""
from __future__ import annotations

import gzip
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from tests.fake_system_container import FakeSystemContainer

from boxmunge.commands.backup_cmd import list_snapshots
from boxmunge.commands.restore import run_restore
from boxmunge.paths import BoxPaths

PROJECT = "myapp"
SNAPSHOT = f"{PROJECT}-2026-10-11T181604.tar.gz.age"
MANIFEST = f"""\
schema_version: 1
id: 01TEST
project: {PROJECT}
source: bundle
hosts: [{PROJECT}.example.com]
services:
  web:
    port: 3000
    routes: [{{path: /}}]
backup:
  type: postgres
  service: db
  dump_command: "pg_dump app"
  restore_command: "psql app"
"""


class Box:
    """A project with one snapshot, and fakes for age and docker that log events."""

    def __init__(self, paths: BoxPaths):
        self.paths = paths
        self.events: list[str] = []
        self.plaintext = b"-- SQL dump\nCREATE TABLE t();\n"
        self.decrypt_error: Exception | None = None
        self.dump_rc = 0
        self.start_error: Exception | None = None
        self.inspect_out = "running healthy"
        self.restore_error: Exception | None = None
        self.restore_rc = 0
        pdir = paths.project_dir(PROJECT)
        pdir.mkdir(parents=True)
        (pdir / "manifest.yml").write_text(MANIFEST)
        (pdir / "compose.yml").write_text("services:\n  db:\n    image: postgres\n")
        paths.project_backups(PROJECT).mkdir()
        (paths.project_backups(PROJECT) / SNAPSHOT).write_bytes(b"encrypted")
        paths.backup_key.write_text("# public key: age1test\nAGE-SECRET-KEY-1TEST\n")

    def _host(self, container_path: str) -> Path:
        assert container_path.startswith("/projects/"), container_path
        return self.paths.projects / container_path.removeprefix("/projects/")

    def age(self, cmd: list[str], **_kw) -> subprocess.CompletedProcess:
        out = self._host(cmd[cmd.index("-o") + 1])
        if "--decrypt" in cmd:
            self.events.append("decrypt")
            if self.decrypt_error:
                raise self.decrypt_error
            out.write_bytes(self.plaintext)
        else:
            self.events.append("encrypt")
            out.write_bytes(b"encrypted safety snapshot")
        return subprocess.CompletedProcess(cmd, 0)

    def dump_run(self, cmd, cwd=None, stdout=None, **_kw):
        self.events.append("dump")
        stdout.write(b"current data")
        return subprocess.CompletedProcess(cmd, self.dump_rc, stderr=b"dump failed")

    def docker_run(self, cmd, cwd=None, stdin=None, stdout=None, **kw):
        """Stands in for subprocess.run (one module object, patched once)."""
        if "exec" in cmd and cmd[-1] == "pg_dump app":
            return self.dump_run(cmd, cwd=cwd, stdout=stdout, **kw)
        if cmd[:2] == ["docker", "compose"] and "up" in cmd:
            self.events.append("start-db")
            if self.start_error:
                raise self.start_error
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(cmd, 0, self.inspect_out, "")
        if "exec" in cmd:
            self.events.append("restore-cmd")
            assert stdin.read() == self.plaintext
            if self.restore_error:
                raise self.restore_error
            return subprocess.CompletedProcess(cmd, self.restore_rc, "", "psql: error")
        raise AssertionError(f"unexpected command {cmd}")

    def leftovers(self) -> list[str]:
        return sorted(p.name for p in self.paths.project_backups(PROJECT).iterdir()
                      if p.name.startswith("."))


@pytest.fixture
def box(paths: BoxPaths, monkeypatch: pytest.MonkeyPatch):
    b = Box(paths)
    FakeSystemContainer(paths, handler=b.age).install(monkeypatch)
    with patch("boxmunge.commands.restore.subprocess.run", side_effect=b.docker_run), \
         patch("boxmunge.commands.restore.time.sleep"), \
         patch("boxmunge.commands.restore.clear_probation_if_active"), \
         patch("boxmunge.commands.restore.compose_down",
               side_effect=lambda *a, **k: b.events.append("down")), \
         patch("boxmunge.commands.restore.compose_up",
               side_effect=lambda *a, **k: b.events.append("up-all")):
        yield b


def _restore(box: Box, **kw) -> int:
    return run_restore(PROJECT, box.paths, snapshot=SNAPSHOT, yes=True, **kw)


class TestVerifiedBeforeStop:
    def test_success_order_and_safety_snapshot(self, box):
        assert _restore(box) == 0
        assert box.events == ["decrypt", "dump", "encrypt", "down", "start-db",
                              "restore-cmd", "up-all"]
        safety = [s.name for s in list_snapshots(box.paths, PROJECT) if s.name.endswith("-prerestore.tar.gz.age")]
        assert len(safety) == 1, "safety snapshot is listed for restore"
        assert box.leftovers() == [], "plaintext and dump temp files removed"

    def test_snapshot_that_does_not_decrypt_leaves_prod_alone(self, box, capsys):
        from boxmunge.backup import BackupError
        box.decrypt_error = BackupError("no identity matched")
        assert _restore(box) == 1
        assert "down" not in box.events and "up-all" not in box.events
        assert "Production was not touched" in capsys.readouterr().err
        assert box.leftovers() == []

    def test_unwritable_backups_dir_leaves_prod_alone(self, box):
        with patch("boxmunge.backup.tempfile.mkdtemp",
                   side_effect=PermissionError(13, "Permission denied")):
            assert _restore(box) == 1
        assert box.events == []

    @pytest.mark.parametrize("plaintext", [b"", gzip.compress(bytes(range(256)) * 64)[:-12]])
    def test_empty_or_truncated_plaintext_leaves_prod_alone(self, box, plaintext, capsys):
        box.plaintext = plaintext
        assert _restore(box) == 1
        assert box.events == ["decrypt"]
        assert "Production was not touched" in capsys.readouterr().err

    def test_valid_gzip_plaintext_passes(self, box):
        box.plaintext = gzip.compress(b"x" * 5000)
        assert _restore(box) == 0

    def test_failed_safety_snapshot_leaves_prod_alone(self, box, capsys):
        box.dump_rc = 1
        assert _restore(box) == 1
        assert "down" not in box.events
        err = capsys.readouterr().err
        assert "safety snapshot" in err and "--no-safety-snapshot" in err

    def test_no_safety_snapshot_skips_the_dump(self, box):
        assert _restore(box, safety_snapshot=False) == 0
        assert "dump" not in box.events


class TestAlwaysRestarted:
    @pytest.mark.parametrize("attr,value", [
        ("start_error", subprocess.TimeoutExpired(["docker"], 120)),
        ("start_error", subprocess.CalledProcessError(1, ["docker"])),
        ("restore_error", PermissionError(13, "Permission denied")),
        ("restore_error", subprocess.TimeoutExpired(["docker"], 600)),
        ("restore_rc", 1),
        ("inspect_out", "running starting"),
    ])
    def test_failure_after_stop_restarts_prod(self, box, attr, value, capsys):
        setattr(box, attr, value)
        assert _restore(box) == 1
        assert box.events[-1] == "up-all"
        assert box.events.index("down") < box.events.index("up-all")
        err = capsys.readouterr().err
        assert "-prerestore.tar.gz.age" in err, "operator is pointed at the safety snapshot"
        assert box.leftovers() == []

    def test_unexpected_error_still_restarts_and_surfaces(self, box):
        box.restore_error = RuntimeError("bug")
        with pytest.raises(RuntimeError):
            _restore(box)
        assert box.events[-1] == "up-all"
