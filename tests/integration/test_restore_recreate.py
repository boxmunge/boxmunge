"""A restore must reach the running application, not just the files on disk.

The backup service here reads its data once at startup and keeps it in
memory, as an app holding an open SQLite file does. A restore that leaves the
container running on its pre-restore state reports success while the app
keeps serving the old data (issue #3).
"""
import shutil
import subprocess
import time
import uuid

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("system_container")]

MANIFEST = """\
schema_version: 1
id: 01JRESTRECREATE00000000000
project: {project}
source: bundle
hosts: [{project}.localhost]
services:
  app:
    internal: true
backup:
  type: custom
  service: app
  dump_command: "cat /data/value"
  restore_command: "cat > /data/value.new && mv /data/value.new /data/value"
"""
# Loads /data/value into its own state once, at startup.
COMPOSE = """\
services:
  app:
    image: alpine:3.20
    init: true
    command: ["sh", "-c", "test -f /data/value || echo original > /data/value;
               cat /data/value > /tmp/loaded; exec sleep 3600"]
    volumes: [data:/data]
volumes:
  data:
"""


def _compose(project_dir, *args: str) -> str:
    # The directory is named for the project, as on a box.
    result = subprocess.run(
        ["docker", "compose", "-p", project_dir.name, "-f", "compose.yml", *args],
        cwd=project_dir, capture_output=True, text=True, timeout=120, check=True,
    )
    return result.stdout.strip()


def _loaded(project_dir) -> str:
    """What the running app loaded at startup."""
    for _ in range(30):
        try:
            return _compose(project_dir, "exec", "-T", "app", "cat", "/tmp/loaded")
        except subprocess.CalledProcessError:
            time.sleep(1)
    pytest.fail("app never started")


@pytest.fixture
def project(int_paths):
    # A name of its own per run: concurrent runs on one Docker daemon would
    # otherwise share (and tear down) one another's containers and volume.
    name = f"rrtest{uuid.uuid4().hex[:8]}"
    project_dir = int_paths.project_dir(name)
    if project_dir.exists():
        shutil.rmtree(project_dir)
    project_dir.mkdir()
    (project_dir / "manifest.yml").write_text(MANIFEST.format(project=name))
    (project_dir / "compose.yml").write_text(COMPOSE)
    try:
        _compose(project_dir, "up", "-d")
        yield int_paths, project_dir
    finally:
        subprocess.run(
            ["docker", "compose", "-p", name, "-f", "compose.yml",
             "down", "-v", "--remove-orphans"],
            cwd=project_dir, capture_output=True, timeout=60, check=False,
        )


def test_restored_data_is_loaded_by_the_backup_service(project) -> None:
    from boxmunge.commands.backup_cmd import run_backup
    from boxmunge.commands.restore import run_restore

    paths, project_dir = project
    name = project_dir.name
    assert _loaded(project_dir) == "original"
    assert run_backup(name, paths) == 0

    _compose(project_dir, "exec", "-T", "app", "sh", "-c", "echo mutated > /data/value")
    _compose(project_dir, "restart", "app")
    assert _loaded(project_dir) == "mutated"

    assert run_restore(name, paths, yes=True, safety_snapshot=False) == 0

    assert _compose(project_dir, "exec", "-T", "app", "cat", "/data/value") == "original"
    assert _loaded(project_dir) == "original", "the app still runs on pre-restore data"
