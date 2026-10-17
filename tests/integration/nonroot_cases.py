# SPDX-License-Identifier: Apache-2.0
"""Non-root deploy cases, run against a real daemon (plain here; the
remapped run is the migration scenario's)."""
from __future__ import annotations

import subprocess
import uuid
from unittest.mock import patch

import yaml

from boxmunge.commands.deploy import run_deploy
from boxmunge.project_registry import add_project, is_registered
from tests.bundle_helpers import manifest_text, place_bundle

BUSYBOX = "busybox:1.36"
SLEEP = ["sleep", "infinity"]


def bundle(project: str, services: dict, *, declare: dict | None = None,
           volumes: tuple[str, ...] = (), files: dict | None = None) -> dict[str, str]:
    # One ULID per project, the same for each of its bundles.
    ulid = ("01" + project.upper()).ljust(26, "0")
    manifest = yaml.safe_load(manifest_text(project, ulid=ulid))
    manifest["schema_version"] = 3
    # A declared service gets an entry holding only its security block; the
    # others an internal entry, so the manifest has services to name.
    manifest["services"] = {
        name: ({"security": declare[name]} if declare and name in declare
               else {"internal": True, "writable": {"external": True}})
        for name in services}
    compose = {"services": services, **({"volumes": {v: {} for v in volumes}} if volumes else {})}
    return {"manifest.yml": yaml.safe_dump(manifest), "compose.yml": yaml.safe_dump(compose),
            **(files or {})}


def deploy(paths, project: str, files: dict[str, str], capsys) -> tuple[int, str]:
    """(exit code, stdout + stderr) of one bundle deploy."""
    if not is_registered(project, paths):
        add_project(project, paths)
    ts = f"2026-10-16T{uuid.uuid4().int % 10**12:012d}"
    place_bundle(paths, project, ts, files)
    with patch("boxmunge.commands.deploy.caddy_reload"):
        rc = run_deploy(project, paths, ref=ts)
    out = capsys.readouterr()
    return rc, out.out + out.err


def compose(paths, project: str, *args: str) -> str:
    return subprocess.run(
        ["docker", "compose", "-p", project, "-f", "compose.yml", "-f", "compose.boxmunge.yml",
         *args], cwd=paths.project_dir(project), check=True, capture_output=True,
        text=True, timeout=300).stdout


def teardown(paths, project: str) -> None:
    from boxmunge.built_images import remove_built_images
    project_dir = paths.project_dir(project)
    if (project_dir / "compose.boxmunge.yml").exists():
        subprocess.run(["docker", "compose", "-p", project, "-f", "compose.yml", "-f",
                        "compose.boxmunge.yml", "down", "-v", "--rmi", "local", "-t", "0"],
                       cwd=project_dir, capture_output=True, timeout=120)
    remove_built_images(project)  # a refused deploy's candidates too


def _health(test: str) -> dict:
    return {"test": ["CMD-SHELL", test], "interval": "1s", "retries": 120}


PG = {"image": "postgres:16-alpine", "environment": {"POSTGRES_PASSWORD": "x"},
      "volumes": ["pgdata:/var/lib/postgresql/data"], "healthcheck": _health("pg_isready -U postgres")}
MYSQL = {"image": "mysql:8.4", "environment": {"MYSQL_ROOT_PASSWORD": "x"},
         "volumes": ["mysqldata:/var/lib/mysql"],
         "healthcheck": _health("mysqladmin ping -h 127.0.0.1 -px --silent")}
NGINX = {"image": "nginx:1.27-alpine", "healthcheck": _health("wget -qO- http://127.0.0.1/")}
IMAGE = {"user": "image", "reason": "the entrypoint starts as root and drops privileges"}


def case_registry_root_refused(paths, p, capsys) -> None:
    rc, out = deploy(paths, p, bundle(p, {"db": PG}, volumes=("pgdata",)), capsys)
    assert rc == 1 and "user: image" in out and "registry image postgres:16-alpine" in out


def case_declared_image_runs(paths, p, capsys) -> None:
    """postgres, mysql and nginx as their images' users, redis as 999:1000,
    each from an entry holding only its security block."""
    services = {"db": PG, "mysql": MYSQL, "web": NGINX,
                "cache": {"image": "redis:7-alpine", "volumes": ["data:/data"],
                          "healthcheck": _health("redis-cli ping | grep -q PONG")}}
    declare = {"db": IMAGE, "mysql": IMAGE, "web": IMAGE, "cache": {"user": "999:1000"}}
    rc, out = deploy(paths, p, bundle(p, services, declare=declare,
                                      volumes=("pgdata", "mysqldata", "data")), capsys)
    assert rc == 0, out
    compose(paths, p, "up", "-d", "--wait")
    overlay = yaml.safe_load((paths.project_dir(p) / "compose.boxmunge.yml").read_text())
    assert overlay["services"]["cache"]["user"] == "999:1000"
    assert not {"read_only", "env_file"} & set(overlay["services"]["db"])  # nothing else changes
    assert "postgres" in compose(paths, p, "exec", "-T", "db", "ps", "-o", "user,comm")
    assert compose(paths, p, "exec", "-T", "cache", "redis-cli", "SAVE").strip() == "OK"


def case_redis_saves_after_recreate(paths, p, capsys) -> None:
    svc = {"cache": {"image": "redis:7-alpine", "volumes": ["data:/data"]}}
    rc, out = deploy(paths, p, bundle(p, svc, declare={"cache": {"user": "999:1000"}},
                                      volumes=("data",)), capsys)
    assert rc == 0, out
    for _ in range(2):
        assert compose(paths, p, "exec", "-T", "cache", "redis-cli", "SAVE").strip() == "OK"
        compose(paths, p, "up", "-d", "--force-recreate")


def _build(p: str, dockerfile: str, volume: str = "data:/data") -> dict[str, str]:
    return bundle(p, {"app": {"build": ".", "command": SLEEP, "volumes": [volume]}},
                  volumes=("data",) if ":" in volume else (),
                  files={"Dockerfile": dockerfile})


def case_image_owned_target_refused(paths, p, capsys) -> None:
    rc, out = deploy(paths, p, _build(p, f"FROM {BUSYBOX}\nRUN mkdir /data\n"), capsys)
    assert rc == 1 and "RUN chown 10001:10001 /data" in out


def case_chowned_target_survives_recreates(paths, p, capsys) -> None:
    rc, out = deploy(paths, p, _build(
        p, f"FROM {BUSYBOX}\nRUN mkdir /data && chown 10001:10001 /data\n"), capsys)
    assert rc == 0, out
    for _ in range(2):
        compose(paths, p, "up", "-d", "--force-recreate")
        compose(paths, p, "exec", "-T", "app", "touch", "/data/x")
    assert compose(paths, p, "exec", "-T", "app", "id", "-u").strip() == "10001"


def case_imageless_target_chowned_once(paths, p, capsys) -> None:
    rc, out = deploy(paths, p, _build(p, f"FROM {BUSYBOX}\n"), capsys)
    assert rc == 0, out
    compose(paths, p, "up", "-d", "--force-recreate")
    compose(paths, p, "exec", "-T", "app", "touch", "/data/y")


def case_anonymous_volume(paths, p, capsys, *, remapped: bool) -> None:
    rc, out = deploy(paths, p, _build(p, f"FROM {BUSYBOX}\n", volume="/scratch"), capsys)
    if remapped:
        assert rc == 1 and "anonymous volume" in out
    else:
        assert rc == 0 and "will block userns-migrate" in out, out


def case_user_change_needs_chown(paths, p, capsys) -> None:
    from boxmunge.commands.data_cmd import run_data_chown
    root = {"app": {"user": "root", "reason": "it ran as root before"}}
    svc = {"app": {"build": ".", "command": SLEEP, "volumes": ["./uploads:/uploads"]}}
    files = {"Dockerfile": f"FROM {BUSYBOX}\n"}
    rc, out = deploy(paths, p, bundle(p, svc, declare=root, files=files), capsys)
    assert rc == 0, out
    compose(paths, p, "exec", "-T", "app", "sh", "-c", "echo x > /uploads/f && chmod 600 /uploads/f")
    rc, out = deploy(paths, p, bundle(p, svc, files=files), capsys)
    assert rc == 1 and f"boxmunge data chown {p} app 10001:10001" in out, out
    assert run_data_chown(paths, p, "app", "10001:10001") == 0
    rc, out = deploy(paths, p, bundle(p, svc, files=files), capsys)
    assert rc == 0, out
    assert compose(paths, p, "exec", "-T", "app", "id", "-u").strip() == "10001"
