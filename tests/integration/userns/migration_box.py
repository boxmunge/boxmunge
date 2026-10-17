"""A small boxmunge box on the dind daemon, for the migration's real-daemon tests.

One registered project: a busybox service with `restart: always` (the old
daemon restarts it at once when it starts), a named volume and a
read-write bind holding files of several owners (a setuid file among them),
and a read-only bind. What the engine needs beyond Docker is stood in
for: the backups and the final checks, Caddy and the system container (not
run here), and the compose guard (the project is started with plain
compose, as the migration would through compose_guard).
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from boxmunge.docker_run import docker_env
from boxmunge.paths import BoxPaths
from boxmunge.project_registry import add_project
from boxmunge.userns import offset as uo
from tests.integration.userns.dockerd import BUSYBOX

PROJECT = "bmsweep"
VOLUME = f"{PROJECT}_data"
COMPOSE = f"""services:
  app:
    image: {BUSYBOX}
    command: ["sleep", "86400"]
    network_mode: none
    restart: always
    volumes:
      - data:/data
      - ./data/uploads:/uploads
      - ./conf:/conf:ro
volumes:
  data:
"""
SEED = ("echo 42 > /data/row && chown 70:70 /data/row && mkdir /data/pg && "
        "echo x > /data/pg/f && chown -R 999:999 /data/pg && chmod 700 /data/pg && "
        "cp /bin/busybox /data/suid && chown 999:999 /data/suid && chmod 4755 /data/suid && "
        "ln -s /etc/passwd /data/lnk")
VIEW = "find /data /uploads -exec stat -c '%n %u %g %a %F' {} + | sort"


def docker(*args: str, check: bool = True, cwd: Path | None = None) -> subprocess.CompletedProcess:
    result = subprocess.run(["docker", *args], env=docker_env(), capture_output=True, text=True,
                            cwd=cwd)
    if check and result.returncode != 0:
        raise AssertionError(f"docker {' '.join(args)}: {result.stderr}")
    return result


def compose_up(paths: BoxPaths) -> None:
    docker("compose", "-p", PROJECT, "up", "-d", "--no-build", "--pull", "never",
           cwd=paths.project_dir(PROJECT))


def make_box(paths: BoxPaths) -> None:
    """The project deployed and seeded, on the running (prior) daemon."""
    paths.config_file.write_text("hostname: dind.localhost\nadmin_email: ops@example.com\n"
                                 "backup_remote: \"remote:box\"\n")
    project = paths.project_dir(PROJECT)
    (project / "data" / "uploads" / "media").mkdir(parents=True)
    (project / "conf").mkdir()
    (project / "conf" / "app.ini").write_text("x=1\n")
    for d in (paths.projects, project, project / "conf"):
        os.chmod(d, 0o755)
    (project / "conf" / "app.ini").chmod(0o644)
    uploads = project / "data" / "uploads"
    (uploads / "a.jpg").write_text("jpg")
    os.chown(uploads / "a.jpg", 1000, 1000)
    os.chown(uploads / "media", 33, 33)
    (uploads / "media" / "b.png").write_text("png")
    os.chown(uploads / "media" / "b.png", 33, 33)
    (project / "manifest.yml").write_text(f"project: {PROJECT}\nhosts: [{PROJECT}.example.com]\n")
    (project / "compose.yml").write_text(COMPOSE)
    add_project(PROJECT, paths)
    docker("pull", "-q", BUSYBOX)
    compose_up(paths)
    docker("exec", container(), "sh", "-c", SEED)


def container() -> str:
    ids = docker("ps", "-q", "--filter", f"label=com.docker.compose.project={PROJECT}").stdout.split()
    assert len(ids) == 1, f"expected one running {PROJECT} container, found {ids}"
    return ids[0]


def view() -> str:
    """What the project's container sees: names, owners, modes."""
    return docker("exec", container(), "sh", "-c", VIEW).stdout + \
        docker("exec", container(), "cat", "/data/row", "/conf/app.ini").stdout


def host_owners(paths: BoxPaths) -> dict[str, tuple[int, int]]:
    root = paths.project_dir(PROJECT) / "data" / "uploads"
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in [*dirnames, *filenames]:
            st = os.lstat(os.path.join(dirpath, name))
            out[os.path.relpath(os.path.join(dirpath, name), root)] = (st.st_uid, st.st_gid)
    return out


def daemon_remapped() -> bool:
    return "name=userns" in json.loads(docker("info", "--format", "{{json .SecurityOptions}}")
                                       .stdout)


def stand_ins(monkeypatch) -> None:
    """What this box does not run, stood in for (module docstring)."""
    from boxmunge.userns import bringup, engine, preflight
    monkeypatch.setattr(engine, "_backups", lambda paths, inv: None)
    monkeypatch.setattr(engine, "_final", lambda paths, j, results: None)
    # The users decision lands with the non-root default (userns PR3).
    monkeypatch.setattr(preflight, "_undeclared_root", lambda paths, r: None)
    monkeypatch.setattr(bringup, "compose_up_platform", lambda *a, **kw: None)
    monkeypatch.setattr(bringup, "connect", lambda paths: None)
    monkeypatch.setattr(bringup, "caddy_reload", lambda *a: None)
    monkeypatch.setattr(bringup, "prepare_compose_override", lambda *a, **kw: None)
    monkeypatch.setattr(bringup, "prepare_caddy_config", lambda *a: None)
    monkeypatch.setattr(bringup, "smoke_ok", lambda *a: True)
    monkeypatch.setattr(bringup, "compose_up_checked", lambda paths, project, **kw:
                        compose_up(paths))


def offset_of(paths: BoxPaths) -> int:
    return uo.recorded_offset(paths) or 0
