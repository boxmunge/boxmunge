# SPDX-License-Identifier: Apache-2.0
"""The projects of the userns VM rehearsal (vm-userns.py), as inbox bundles.

Each project has a v1 that boxmunge 0.10.1 deploys as it is, and a v2 that
does what `userns-migrate --check` asks for on the beta: who each registry
service runs as (`security.user`), and a named volume for postgres's
anonymous one. vmapp has a v3, deployed during the soak.

- vmdb: postgres, mariadb and redis on named volumes; backed up with pg_dump.
- vmanon: postgres on its image's anonymous VOLUME (v2 mounts a named one).
- vmweb: nginx and a node server behind Caddy.
- vmapp: a built busybox httpd (the beta's 10001 default) serving a
  read-write bind, with `staging.copy_data`.

The database services keep a writable root (`read_only: false`): the
rehearsal is about who owns their data, not about their root filesystems.
"""
from __future__ import annotations

import io
import tarfile
import time
from pathlib import Path

import yaml

REFS = {"v1": "2026-10-16T090000000000", "v2": "2026-10-16T100000000000",
        "v3": "2026-10-16T110000000000"}
PROJECTS = ("vmdb", "vmanon", "vmweb", "vmapp")
IDS = {p: ("01VMUSERNS" + str(i)).ljust(26, "0") for i, p in enumerate(PROJECTS)}
IMAGE = {"user": "image", "reason": "the image's entrypoint starts as root and drops to its own user"}
HTTPD = ["httpd", "-f", "-p", "8080", "-h", "/srv"]


def _manifest(project: str, services: dict, *, backup: dict | None = None,
              hosts: bool = False, **extra) -> str:
    doc = {"schema_version": 3, "id": IDS[project], "project": project, "source": "bundle",
           "hosts": [f"{project}.localhost"] if hosts else [f"{project}.example.com"],
           "services": services, "backup": backup or {"type": "none"}, **extra}
    return yaml.safe_dump(doc, sort_keys=False)


def _db(image: str, env: dict, volume: str | None, target: str) -> dict:
    svc = {"image": image, "environment": env, "read_only": False, "restart": "unless-stopped"}
    if volume:
        svc["volumes"] = [f"{volume}:{target}"]
    return svc


def vmdb(version: str) -> dict[str, str]:
    compose = {"services": {
        "db": _db("postgres:16-alpine", {"POSTGRES_PASSWORD": "vm", "POSTGRES_DB": "vm"},
                  "pgdata", "/var/lib/postgresql/data"),
        "maria": _db("mariadb:11", {"MARIADB_ROOT_PASSWORD": "vm", "MARIADB_DATABASE": "vm"},
                     "mariadata", "/var/lib/mysql"),
        "cache": _db("redis:7-alpine", {}, "redisdata", "/data"),
    }, "volumes": {"pgdata": {}, "mariadata": {}, "redisdata": {}}}
    db = {"internal": True, "writable": {"external": True}}
    services = {"db": db} if version == "v1" else {
        "db": {**db, "security": IMAGE}, "maria": {"security": IMAGE},
        "cache": {"security": {"user": "999:1000"}}}
    backup = {"type": "postgres", "service": "db", "dump_command": "pg_dump -U postgres vm",
              "restore_command": "psql -U postgres vm"}
    return {"manifest.yml": _manifest("vmdb", services, backup=backup),
            "compose.yml": yaml.safe_dump(compose)}


def vmanon(version: str) -> dict[str, str]:
    named = version != "v1"
    db = _db("postgres:16-alpine", {"POSTGRES_PASSWORD": "vm", "POSTGRES_DB": "vm"},
             "pgdata" if named else None, "/var/lib/postgresql/data")
    compose = {"services": {"db": db}, **({"volumes": {"pgdata": {}}} if named else {})}
    entry = {"internal": True, "writable": {"external": True}}
    services = {"db": {**entry, "security": IMAGE} if named else entry}
    return {"manifest.yml": _manifest("vmanon", services), "compose.yml": yaml.safe_dump(compose)}


NODE = "require('http').createServer((q, s) => s.end('node ' + process.getuid())).listen(3000)"


def vmweb(version: str) -> dict[str, str]:
    compose = {"services": {
        "web": {"image": "nginx:1.27-alpine", "read_only": False},
        "api": {"image": "node:22-alpine", "command": ["node", "-e", NODE]},
    }}
    web = {"port": 80, "routes": [{"path": "/"}]}
    api = {"port": 3000, "routes": [{"path": "/api*"}]}
    if version != "v1":
        web["security"] = IMAGE
        api["security"] = {"user": "1000:1000"}  # the image's node user
    return {"manifest.yml": _manifest("vmweb", {"web": web, "api": api}, hosts=True),
            "compose.yml": yaml.safe_dump(compose)}


def vmapp(version: str) -> dict[str, str]:
    compose = {"services": {"web": {"build": ".", "command": HTTPD,
                                    "volumes": ["./data/uploads:/srv"]}}}
    web = {"port": 8080, "routes": [{"path": "/"}], "writable": {"external": True}}
    files = {"manifest.yml": _manifest("vmapp", {"web": web}, hosts=True,
                                       staging={"copy_data": True}),
             "compose.yml": yaml.safe_dump(compose),
             "Dockerfile": "FROM busybox:1.36\n",
             "VERSION": version}
    return files


BUILDERS = {"vmdb": vmdb, "vmanon": vmanon, "vmweb": vmweb, "vmapp": vmapp}
VERSIONS = {"vmdb": ("v1", "v2"), "vmanon": ("v1", "v2"), "vmweb": ("v1", "v2"),
            "vmapp": ("v1", "v2", "v3")}


def _add(tar: tarfile.TarFile, name: str, text: str) -> None:
    data = text.encode()
    info = tarfile.TarInfo(name)
    info.size, info.mode, info.mtime = len(data), 0o644, int(time.time())
    tar.addfile(info, io.BytesIO(data))


def write_bundles(out: Path) -> None:
    """Inbox bundles named as reception names them: <project>-<ref>.tar.gz."""
    out.mkdir(parents=True, exist_ok=True)
    for project, build in BUILDERS.items():
        for version in VERSIONS[project]:
            with tarfile.open(out / f"{project}-{REFS[version]}.tar.gz", "w:gz") as tar:
                for name, text in build(version).items():
                    _add(tar, f"{project}/{name}", text)


# Data written before the migration and read back after each step:
# (description, root shell command that writes, root shell command whose
# output must equal `expect`).
def _exec(project: str, service: str, cmd: str) -> str:
    return (f'docker exec "$(docker ps -q --filter label=com.docker.compose.project={project} '
            f'--filter label=com.docker.compose.service={service})" {cmd}')


def _insert(value: str) -> str:
    return f"\"create table t (v text); insert into t values ('{value}')\""


SEED = [
    ("postgres row", _exec("vmdb", "db", f"psql -U postgres vm -c {_insert('pg')}"),
     _exec("vmdb", "db", "psql -U postgres vm -tAc 'select v from t'"), "pg"),
    ("mariadb row", _exec("vmdb", "maria", f"mariadb -uroot -pvm vm -e {_insert('maria')}"),
     _exec("vmdb", "maria", "mariadb -uroot -pvm vm -N -e 'select v from t'"), "maria"),
    ("redis key", _exec("vmdb", "cache", "sh -c 'redis-cli set k redis && redis-cli save'"),
     _exec("vmdb", "cache", "redis-cli get k"), "redis"),
    ("anonymous postgres row", _exec("vmanon", "db", f"psql -U postgres vm -c {_insert('anon')}"),
     _exec("vmanon", "db", "psql -U postgres vm -tAc 'select v from t'"), "anon"),
    ("an upload", "echo upload > /opt/boxmunge/projects/vmapp/data/uploads/index.html",
     "cat /opt/boxmunge/projects/vmapp/data/uploads/index.html", "upload"),
]
