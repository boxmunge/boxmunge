"""A real postgres volume and a hostile bind tree, bit for bit, across a
migration, its rollback and kills in the middle of the shifts.

The bind tree holds what a data tree may: hard links, a FIFO, a socket, a
512 MiB sparse file, setuid/setgid files, setgid and sticky directories,
user xattrs, links out of the tree and to /, nobody's file and 300
owners. Every entry's owners, mode, size, blocks, link count, mtime,
target, xattrs and content must come back exactly, shifted by S while
migrated; /etc/shadow and / are never touched."""
from __future__ import annotations

import hashlib
import json
import os
import socket
import stat
import subprocess
import time
from pathlib import Path

import pytest

from boxmunge.docker_run import docker_env
from boxmunge.paths import BoxPaths
from boxmunge.project_registry import add_project
from boxmunge.userns.engine import migrate
from boxmunge.userns.journal import load_journal
from boxmunge.userns.rollback import rollback
from tests.integration.userns.conftest import USERNS_DIND
from tests.integration.userns.crashsweep import count, crash_before
from tests.integration.userns.dockerd import FakeTimers, ProcessDaemon

pytestmark = USERNS_DIND
PROJECT = "rvpg"
PG = "postgres:16-alpine"
COMPOSE = f"""services:
  db:
    image: {PG}
    environment: {{POSTGRES_PASSWORD: pw}}
    network_mode: none
    restart: always
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./data/files:/files
volumes:
  pgdata:
"""


def docker(*args, check=True, cwd=None):
    r = subprocess.run(["docker", *args], env=docker_env(), capture_output=True, text=True,
                       cwd=cwd)
    if check and r.returncode != 0:
        raise AssertionError(f"docker {' '.join(args)}: {r.stderr}")
    return r


def up(paths):
    docker("compose", "-p", PROJECT, "up", "-d", "--no-build", "--pull", "never",
           cwd=paths.project_dir(PROJECT))


def cid():
    ids = docker("ps", "-q", "--filter", f"label=com.docker.compose.project={PROJECT}").stdout.split()
    assert len(ids) == 1, ids
    return ids[0]


def psql(sql):
    deadline = time.monotonic() + 90
    while True:
        r = docker("exec", cid(), "psql", "-U", "postgres", "-tAc", sql, check=False)
        if r.returncode == 0:
            return r.stdout.strip()
        if time.monotonic() > deadline:
            raise AssertionError(r.stderr)
        time.sleep(1)


def stand_ins(mp):
    from boxmunge.userns import bringup, engine
    mp.setattr(engine, "_backups", lambda paths, inv: None)
    mp.setattr(engine, "_final", lambda paths, j, results: None)
    mp.setattr(bringup, "compose_up_platform", lambda *a, **kw: None)
    mp.setattr(bringup, "connect", lambda paths: None)
    mp.setattr(bringup, "caddy_reload", lambda *a: None)
    mp.setattr(bringup, "prepare_compose_override", lambda *a, **kw: None)
    mp.setattr(bringup, "prepare_caddy_config", lambda *a: None)
    mp.setattr(bringup, "smoke_ok", lambda *a: True)
    mp.setattr(bringup, "compose_up_checked", lambda paths, project, **kw: up(paths))


def make_files(files: Path):
    files.mkdir(parents=True)
    (files / "a").write_text("a"); os.chown(files / "a", 1000, 1000); os.chmod(files / "a", 0o640)
    (files / "hl1").write_text("hl"); os.link(files / "hl1", files / "hl2")
    os.chown(files / "hl1", 33, 33)
    os.mkfifo(files / "fifo"); os.chown(files / "fifo", 70, 70)
    s = socket.socket(socket.AF_UNIX); s.bind(str(files / "sock")); s.close()
    os.chown(files / "sock", 999, 999, follow_symlinks=False)
    with open(files / "sparse", "wb") as f:
        f.seek(512 * 1024 * 1024); f.write(b"end")
    (files / "sgid_dir").mkdir(); os.chown(files / "sgid_dir", 0, 33); os.chmod(files / "sgid_dir", 0o2775)
    (files / "sticky").mkdir(); os.chmod(files / "sticky", 0o1777)
    (files / "suid").write_bytes(b"#!/bin/sh\n"); os.chown(files / "suid", 0, 0); os.chmod(files / "suid", 0o4755)
    (files / "sgidx").write_bytes(b"#!/bin/sh\n"); os.chown(files / "sgidx", 0, 50); os.chmod(files / "sgidx", 0o2755)
    (files / "xattr").write_text("x")
    try:
        os.setxattr(files / "xattr", "user.rv", b"1")
    except OSError as e:
        print("no user xattr:", e)
    os.symlink("/etc/shadow", files / "link_out"); os.chown(files / "link_out", 1000, 1000, follow_symlinks=False)
    os.symlink("/", files / "link_root")
    (files / "nobody").write_text("n"); os.chown(files / "nobody", 65534, 65534)
    deep = files / "deep" / "a" / "b" / "c"
    deep.mkdir(parents=True); (deep / "f").write_text("f"); os.chown(deep / "f", 5000, 5000)
    for i in range(300):
        p = files / "many" / f"{i:03d}"
        p.parent.mkdir(exist_ok=True); p.write_text(str(i)); os.chown(p, 1000 + i, 1000 + i)


def manifest(root: Path) -> dict:
    out, groups = {}, {}
    def one(path: Path, rel: str):
        st = os.lstat(path)
        key = (st.st_dev, st.st_ino)
        grp = groups.setdefault(key, len(groups)) if st.st_nlink > 1 and not stat.S_ISDIR(st.st_mode) else None
        xs = sorted((n, os.getxattr(path, n, follow_symlinks=False).hex())
                    for n in os.listxattr(path, follow_symlinks=False)) if not stat.S_ISLNK(st.st_mode) else []
        h = None
        if stat.S_ISREG(st.st_mode):
            with open(path, "rb") as f:
                h = hashlib.sha256(f.read()).hexdigest()
        out[rel] = dict(uid=st.st_uid, gid=st.st_gid, mode=oct(st.st_mode), size=st.st_size,
                        blocks=st.st_blocks, nlink=st.st_nlink, mtime=st.st_mtime_ns, grp=grp,
                        link=os.readlink(path) if stat.S_ISLNK(st.st_mode) else None, xattr=xs, sha=h)
    one(root, ".")
    for dp, dns, fns in os.walk(root):
        for n in dns + fns:
            p = Path(dp) / n
            one(p, str(p.relative_to(root)))
    return out


def vol_dir():
    return Path(docker("volume", "inspect", "--format", "{{.Mountpoint}}", f"{PROJECT}_pgdata").stdout.strip())


def snapshot(paths):
    return {"vol": manifest(vol_dir()), "bind": manifest(paths.project_dir(PROJECT) / "data" / "files"),
            "shadow": tuple(os.lstat("/etc/shadow")[:7]), "root": tuple(os.lstat("/")[4:6])}


def shifted(before, s):
    out = json.loads(json.dumps(before))
    for tree in ("vol", "bind"):
        for e in out[tree].values():
            e["uid"] += s; e["gid"] += s
    out["shadow"], out["root"] = before["shadow"], before["root"]
    return out


def norm(snap):
    return json.loads(json.dumps(snap))


_META = ("uid", "gid", "mode", "link", "nlink")


def diff(a, b):
    """bind: everything; vol (postgres rewrites files when it runs): owners,
    modes, links of entries in both, and the owners of new ones in b's range."""
    lines = []
    for k in sorted(set(a["bind"]) | set(b["bind"])):
        if a["bind"].get(k) != b["bind"].get(k):
            lines.append(f"bind/{k}: {a['bind'].get(k)} != {b['bind'].get(k)}")
    ref_uids = {e["uid"] for e in b["vol"].values()} | {e["gid"] for e in b["vol"].values()}
    for k in sorted(set(a["vol"]) | set(b["vol"])):
        x, y = a["vol"].get(k), b["vol"].get(k)
        if x and y:
            if any(x[f] != y[f] for f in _META):
                lines.append(f"vol/{k}: {[x[f] for f in _META]} != {[y[f] for f in _META]}")
        elif x and (x["uid"] not in ref_uids or x["gid"] not in ref_uids):
            lines.append(f"vol/{k} new with owner {x['uid']}:{x['gid']}")
    if list(a["shadow"])[4:6] != list(b["shadow"])[4:6]:
        lines.append(f"shadow owner: {a['shadow']} != {b['shadow']}")
    if list(a["root"]) != list(b["root"]):
        lines.append(f"root: {a['root']} != {b['root']}")
    return lines[:30]


@pytest.fixture(scope="module")
def box(tmp_path_factory):
    root = tmp_path_factory.mktemp("rv") / "boxmunge"
    for sub in ("config", "projects", "state/deploy", "state/health", "logs", "caddy/sites",
                "system", "upgrade-state"):
        (root / sub).mkdir(parents=True)
    paths = BoxPaths(root=root)
    with pytest.MonkeyPatch.context() as mp:
        stand_ins(mp)
        paths.config_file.write_text("hostname: dind.localhost\nadmin_email: ops@example.com\n"
                                     "backup_remote: \"remote:box\"\n")
        project = paths.project_dir(PROJECT)
        project.mkdir()
        for d in (paths.projects, project):
            os.chmod(d, 0o755)
        make_files(project / "data" / "files")
        (project / "manifest.yml").write_text(
            f"project: {PROJECT}\nhosts: [{PROJECT}.example.com]\nservices:\n  db:\n"
            f"    security:\n      user: image\n      reason: postgres entrypoint drops to 70\n")
        (project / "compose.yml").write_text(COMPOSE)
        (project / "compose.boxmunge.yml").write_text("services:\n  db: {}\n")
        add_project(PROJECT, paths)
        docker("pull", "-q", PG)
        docker("network", "create", "--subnet", "172.31.251.0/24", "boxmunge-proxy")
        up(paths)
        psql("create table t(i int); insert into t select generate_series(1,5000); checkpoint;")
        yield paths, root.parent / "img"
        j = load_journal(paths)
        if j is not None and j.phase not in ("rolled-back",):
            try:
                rollback(paths, daemon=ProcessDaemon(), timers=FakeTimers(), images_dir=root.parent / "img")
            except Exception as e:
                print("teardown rollback failed", e)
        docker("compose", "-p", PROJECT, "down", "-v", cwd=project, check=False)
        docker("network", "rm", "boxmunge-proxy", check=False)


def _m(paths, img):
    migrate(paths, daemon=ProcessDaemon(), timers=FakeTimers(), images_dir=img)


def _r(paths, img):
    rollback(paths, daemon=ProcessDaemon(), timers=FakeTimers(), images_dir=img)


def _stopped_snapshot(paths):
    docker("compose", "-p", PROJECT, "stop", cwd=paths.project_dir(PROJECT))
    snap = norm(snapshot(paths))
    docker("compose", "-p", PROJECT, "start", cwd=paths.project_dir(PROJECT))
    return snap


def test_every_entry_comes_back_bit_for_bit(box) -> None:
    paths, img = box
    before = _stopped_snapshot(paths)
    assert psql("select count(*) from t") == "5000"
    labels = count(lambda: _m(paths, img))
    s = load_journal(paths).offset
    assert psql("select count(*) from t") == "5000"
    docker("compose", "-p", PROJECT, "stop", cwd=paths.project_dir(PROJECT))
    after = norm(snapshot(paths))
    docker("compose", "-p", PROJECT, "start", cwd=paths.project_dir(PROJECT))
    d = diff(after, shifted(before, s))
    print("migrate diff:", d)
    assert not d
    _r(paths, img)
    assert psql("select count(*) from t") == "5000"
    d = diff(_stopped_snapshot(paths), before)
    print("rollback diff:", d)
    assert not d
    chowns = [i + 1 for i, l in enumerate(labels) if l.startswith("fchown") or l.startswith("chown")]
    chmods = [i + 1 for i, l in enumerate(labels) if l == "fchmod@visit"]
    loads = [i + 1 for i, l in enumerate(labels) if l.startswith("docker load")]
    print("labels", len(labels), "chowns", len(chowns), "chmods", chmods, "loads", loads)
    points = sorted({chowns[len(chowns) // 3], chowns[2 * len(chowns) // 3], *chmods[:2], *loads[-1:]})
    for k, n in enumerate(points):
        assert crash_before(n, lambda: _m(paths, img)) == 137, (n, labels[n - 1])
        if k % 2 == 0:
            _m(paths, img)
            assert psql("select count(*) from t") == "5000"
            docker("compose", "-p", PROJECT, "stop", cwd=paths.project_dir(PROJECT))
            d = diff(norm(snapshot(paths)), shifted(before, s))
            docker("compose", "-p", PROJECT, "start", cwd=paths.project_dir(PROJECT))
            print(f"kill {n} {labels[n-1]} resumed diff:", d)
            assert not d
        _r(paths, img)
        assert psql("select count(*) from t") == "5000"
        d = diff(_stopped_snapshot(paths), before)
        print(f"kill {n} {labels[n-1]} rollback diff:", d)
        assert not d
