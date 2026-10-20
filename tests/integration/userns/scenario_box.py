# SPDX-License-Identifier: Apache-2.0
"""A small real box on the dind daemon, for the end-to-end migration scenario.

Unlike migration_box (one plain-compose project, the platform stood in for),
this box runs the platform itself: the system container built from
system/compose.yml and Caddy from caddy/compose.yml, each started as the
upgrade starts them; projects go through run_deploy from inbox bundles; the
backups are real (pg_dump, age in the system container, rclone to a local
remote). Only the migration's closing report (cve-scan, check-all,
self-test: tools and a canary this box does not have) is stood in for.
The box runs as root with root as its deploy user, so the system container
runs as 0:0 (connect() checks it is the projects directory's owner).
"""
from __future__ import annotations

import http.client
import os
import shutil
import ssl
import subprocess
from pathlib import Path

import yaml

from boxmunge.commands.deploy import run_deploy
from boxmunge.compose_guard import compose_up_platform
from boxmunge.docker_run import docker_env
from boxmunge.paths import BoxPaths
from boxmunge.project_registry import add_project, is_registered
from tests.bundle_helpers import place_bundle
from tests.integration.userns.dockerd import BUSYBOX

REPO = Path(__file__).resolve().parents[3]
PG = "postgres:16-alpine"
# Inside the system container's /tmp (its tmpfs): rclone runs there, so a
# local remote must be a path it can write.
REMOTE = "local:/tmp/offsite"
HOSTS = Path("/etc/hosts")


def sh(*cmd: str, check: bool = True, timeout: int = 900) -> str:
    result = subprocess.run(list(cmd), env=docker_env(), capture_output=True, text=True,
                            timeout=timeout)
    if check and result.returncode != 0:
        raise AssertionError(f"{' '.join(cmd)} exited {result.returncode}: {result.stderr}")
    return result.stdout


def make_box(root: Path) -> BoxPaths:
    """The platform up on the running (prior) daemon, as install.sh leaves it."""
    paths = BoxPaths(root=root)
    for sub in ("config/rclone", "projects", "state/deploy", "state/health", "logs",
                "caddy/sites", "caddy/maintenance", "system", "inbox", "upgrade-state"):
        (root / sub).mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text("hostname: dind.localhost\nadmin_email: ops@example.com\n"
                                 f"backup_remote: \"{REMOTE}\"\n")
    (paths.rclone_config_dir / "rclone.conf").write_text("[local]\ntype = local\n")
    sh("age-keygen", "-o", str(paths.backup_key))
    os.chmod(paths.backup_key, 0o640)
    for d in (root, paths.projects, paths.config, paths.rclone_config_dir):
        os.chmod(d, 0o755)
    for name in ("Dockerfile", "compose.yml"):
        shutil.copy(REPO / "system" / name, paths.system / name)
    (paths.system / ".env").write_text(
        f"BOXMUNGE_UID=0\nBOXMUNGE_GID=0\nBOXMUNGE_CONFIG={paths.config}\n"
        f"BOXMUNGE_PROJECTS={paths.projects}\n")
    shutil.copy(REPO / "caddy" / "compose.yml", paths.caddy / "compose.yml")
    shutil.copytree(REPO / "caddy" / "maintenance", paths.caddy / "maintenance",
                    dirs_exist_ok=True)
    paths.caddyfile.write_text("{\n    email ops@example.com\n}\n\n"
                               "import /etc/caddy/sites/*.conf\n")
    os.chmod(paths.caddyfile, 0o640)  # install.sh's mode: the migration makes it 0644
    sh("docker", "network", "create", "boxmunge-proxy")
    compose_up_platform(paths.system, ["compose.yml"], "system", build=True)
    compose_up_platform(paths.caddy, ["compose.yml"], "caddy", build=False)
    return paths


def deploy(paths: BoxPaths, project: str, files: dict[str, str], ts: str) -> int:
    """One bundle deploy through run_deploy, Caddy reloaded for real."""
    if not is_registered(project, paths):
        add_project(project, paths)
    place_bundle(paths, project, ts, files)
    return run_deploy(project, paths, ref=ts)


def container(compose_project: str, service: str) -> str:
    ids = sh("docker", "ps", "-q", "--filter", f"label=com.docker.compose.project={compose_project}",
             "--filter", f"label=com.docker.compose.service={service}").split()
    assert len(ids) == 1, f"expected one running {compose_project}/{service}, found {ids}"
    return ids[0]


def in_container(compose_project: str, service: str, script: str) -> str:
    return sh("docker", "exec", container(compose_project, service), "sh", "-c", script)


def psql(project: str, sql: str) -> str:
    return in_container(project, "db", f"psql -U shop -d shop -tAc {sql!r}").strip()


def wait_for_db(project: str) -> None:
    in_container(project, "db", "for i in $(seq 120); do pg_isready -U shop -d shop -q && "
                                "psql -U shop -d shop -c 'select 1' >/dev/null 2>&1 && exit 0; "
                                "sleep 1; done; exit 1")


def owners(path: Path) -> dict[str, tuple[int, int, int]]:
    """Every entry's (uid, gid, mode) as a container on this daemon sees it."""
    out = sh("docker", "run", "--rm", "--network", "none", "-v", f"{path}:/x:ro", BUSYBOX,
             "sh", "-c", "cd /x && find . -exec stat -c '%n %u %g %a' {} +")
    rows = (line.rsplit(" ", 3) for line in out.splitlines())
    return {n: (int(u), int(g), int(m, 8)) for n, u, g, m in rows}


def through_caddy(host: str, path: str) -> tuple[int, str]:
    """GET https://<host><path> through Caddy's published 443 (its internal
    CA serves *.localhost names)."""
    if host not in HOSTS.read_text():
        with HOSTS.open("a") as f:
            f.write(f"127.0.0.1 {host}\n")
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    conn = http.client.HTTPSConnection(host, 443, context=ctx, timeout=30)
    try:
        conn.request("GET", path)
        response = conn.getresponse()
        return response.status, response.read().decode(errors="replace")
    finally:
        conn.close()


def _ulid(project: str) -> str:
    return ("01" + project.upper()).ljust(26, "0")[:26]


def shop_files(project: str) -> dict[str, str]:
    """A built web service (the 10001 default) serving a read-write bind, a
    read-only bind, a named volume the image owns, and postgres declared as
    its image's user, backed up with pg_dump."""
    manifest = {
        "schema_version": 3, "id": _ulid(project), "project": project, "source": "bundle",
        "hosts": [f"{project}.localhost"],
        "services": {
            "web": {"port": 8080, "routes": [{"path": "/"}], "writable": {"external": True}},
            # Only its user declared: postgres keeps its writable root.
            "db": {"security": {"user": "image", "reason": "postgres starts as root and "
                                                           "drops to its own user"}},
        },
        "backup": {"type": "postgres", "service": "db", "dump_command": "pg_dump -U shop shop",
                   "restore_command": "psql -U shop shop"},
    }
    compose = {
        "services": {
            "web": {"build": ".", "command": ["httpd", "-f", "-p", "8080", "-h", "/uploads"],
                    "restart": "always",
                    "volumes": ["./data/uploads:/uploads", "./conf:/etc/app:ro", "cache:/cache"]},
            "db": {"image": PG, "restart": "always",
                   "environment": {"POSTGRES_USER": "shop", "POSTGRES_PASSWORD": "shop"},
                   "volumes": ["pgdata:/var/lib/postgresql/data"]},
        },
        "volumes": {"cache": {}, "pgdata": {}},
    }
    return {"manifest.yml": yaml.safe_dump(manifest), "compose.yml": yaml.safe_dump(compose),
            "Dockerfile": f"FROM {BUSYBOX}\nRUN mkdir /cache && chown 10001:10001 /cache\n",
            "conf/app.ini": "[app]\nname = shop\n"}


def anon_files(project: str, *, named: bool) -> dict[str, str]:
    """A service keeping data at /held: in an anonymous volume, or (named)
    in the volume `held`."""
    manifest = {
        "schema_version": 3, "id": _ulid(project), "project": project, "source": "bundle",
        "hosts": [f"{project}.localhost"],
        "services": {"keeper": {"internal": True, "writable": {"external": True},
                                "security": {"user": "image", "reason": "a test fixture"}}},
        "backup": {"type": "none"},
    }
    svc = {"image": BUSYBOX, "command": ["sh", "-c", "trap 'exit 0' TERM; sleep 86400 & wait"],
           "network_mode": "none", "volumes": ["held:/held"] if named else ["/held"]}
    compose = {"services": {"keeper": svc}, **({"volumes": {"held": {}}} if named else {})}
    return {"manifest.yml": yaml.safe_dump(manifest), "compose.yml": yaml.safe_dump(compose)}
