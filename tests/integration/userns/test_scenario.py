# SPDX-License-Identifier: Apache-2.0
"""A whole box migrated, soaked, rolled back, migrated again and committed,
on a real daemon (spec "Testing — Real Docker"; one run per matrix entry, so
once from each prior store).

The tests run in order on one box (scenario_box): each starts from where the
previous one left it, and says so in its first assertion.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from boxmunge.commands.backup_cmd import list_snapshots, run_backup
from boxmunge.commands.data_cmd import run_data_adopt
from boxmunge.commands.install_abandon import run_abandon
from boxmunge.commands.userns_cmd import run_check
from boxmunge.commands.project_delete_cmd import run_project_delete
from boxmunge.lifecycle import BlockReason, is_blocked, refuse_if_blocked
from boxmunge.paths import BoxPaths
from boxmunge.userns import commit as commit_mod
from boxmunge.userns import engine, steps
from boxmunge.userns import offset as uo
from boxmunge.userns.commit import commit
from boxmunge.userns.inventory import take_inventory
from boxmunge.userns.journal import FORWARD, load_journal
from boxmunge.userns.marker import migration_in_progress
from boxmunge.userns.preflight import preflight
from boxmunge.userns.rollback import rollback
from boxmunge.userns.switch import host_ids
from tests.integration.userns import scenario_box as sb
from tests.integration.userns.conftest import USERNS_DIND, ensure_identity
from tests.integration.userns.dockerd import (
    BUSYBOX, FakeTimers, ProcessDaemon, prior_daemon_json, write_daemon_json,
)

pytestmark = USERNS_DIND

PLANT = ("echo a > /x/root0600 && chmod 600 /x/root0600 && "
         "echo b > /x/pg && chown 70:70 /x/pg && chmod 644 /x/pg && "
         "echo c > /x/suid && chown 999:999 /x/suid && chmod 4755 /x/suid && "
         "mkdir /x/sub && chown 999:1000 /x/sub && chmod 2770 /x/sub")


# The box lives on the dind volume's filesystem (the container's overlayfs
# rootfs keeps no ACLs), bind-mounted outside /var/lib/docker, which the
# compose validator protects: as /opt shares a box's root filesystem with
# Docker's root.
STORE = Path("/var/lib/docker/boxmunge-scenario")
WORK = Path("/srv/boxmunge-scenario")


@pytest.fixture(scope="module")
def box():
    work = WORK
    STORE.mkdir()
    work.mkdir()
    subprocess.run(["mount", "--bind", str(STORE), str(work)], check=True)
    paths = sb.make_box(work / "boxmunge")
    images = work / "userns" / "images"  # in a root-only directory, as on a box
    with pytest.MonkeyPatch.context() as mp:
        # The closing report needs a scanner and the canary; it only reports.
        mp.setattr(engine, "_final", lambda paths, j, results: None)
        assert sb.deploy(paths, "shop", sb.shop_files("shop"), "2026-10-16T090000000000") == 0
        sb.wait_for_db("shop")
        sb.psql("shop", "create table t (v int); insert into t values (42)")
        uploads = paths.project_dir("shop") / "data" / "uploads"
        sb.sh("docker", "run", "--rm", "--network", "none", "-v", f"{uploads}:/x", BUSYBOX,
              "sh", "-c", PLANT)
        # Data no container mounts (a removed service's): reported, never shifted.
        exports = paths.project_dir("shop") / "data" / "old-exports"
        exports.mkdir()
        (exports / "dump.sql").write_text("-- old\n")
        os.chown(exports / "dump.sql", 1234, 1234)
        try:
            yield paths, images
        finally:
            try:
                _teardown()
            finally:
                subprocess.run(["umount", str(work)], check=True)


def _clean_daemon() -> None:
    for name in sb.sh("docker", "ps", "-aq").split():
        sb.sh("docker", "rm", "-f", "-v", name)
    sb.sh("docker", "volume", "prune", "-af")
    sb.sh("docker", "network", "rm", "boxmunge-proxy", check=False)  # absent after some failures


def _teardown() -> None:
    """Leave both stores empty of this box and the daemon on the prior one.
    The remapped root outlives a commit, and later modules switch to it
    (remapped_daemon), so it is emptied too, whichever daemon.json a failed
    test left behind; then the daemon restarts on the prior daemon.json and
    that store is emptied."""
    daemon = ProcessDaemon()
    daemon.stop()
    daemon.start()  # on whatever daemon.json the scenario left
    _clean_daemon()
    daemon.stop()
    write_daemon_json(prior_daemon_json())
    daemon.start()
    _clean_daemon()


class MarkedTimers(FakeTimers):
    """FakeTimers that also looks at the box at the moment the downtime
    starts: the marker is set before the timers stop, and a project command
    refuses on it."""

    def __init__(self, paths: BoxPaths) -> None:
        super().__init__()
        self.paths = paths
        self.at_stop: list[tuple[str | None, bool]] = []

    def stop_all(self) -> None:
        super().stop_all()
        block = is_blocked("shop", self.paths)
        self.at_stop.append((migration_in_progress(self.paths),
                             block is not None and block.reason is BlockReason.MIGRATING))


def _check(paths: BoxPaths, images: Path):
    s = uo.allocate_offset(uo.ETC, host_ids())
    return preflight(paths, take_inventory(paths), direction=FORWARD, offset=s,
                     images_dir=images)


def _migrate(paths: BoxPaths, images: Path, timers: FakeTimers | None = None):
    return engine.migrate(paths, daemon=ProcessDaemon(), timers=timers or FakeTimers(),
                          images_dir=images)


def _rollback(paths: BoxPaths, images: Path, timers: FakeTimers | None = None):
    return rollback(paths, daemon=ProcessDaemon(), timers=timers or FakeTimers(),
                    images_dir=images)


@pytest.fixture
def alerts(monkeypatch):
    """Every alert the migration, its rollback and its commit send."""
    sent: list[str] = []
    for mod in (steps, commit_mod):
        monkeypatch.setattr(mod, "notify", lambda paths, title, *a, **kw: sent.append(title))
    return sent


def _daemon_remapped() -> bool:
    return "name=userns" in json.loads(sb.sh("docker", "info", "--format",
                                             "{{json .SecurityOptions}}"))


def test_1_check_reports_exactly_the_planted_problems(box, capsys) -> None:
    paths, images = box
    report = _check(paths, images)
    assert report.ok, report.text()
    assert "old-exports is not mounted by any container" in report.text()
    shop = paths.project_dir("shop")
    uploads = shop / "data" / "uploads"
    planted = {
        "0600 read-only bind": "read-only bind " + str(shop / "conf"),
        "id 70000": "uid 70000 cannot be mapped",
        "acl": "posix_acl_access",
        "nested mount": "a mount inside the tree",
        "foreign container": "container bm-foreign (no compose project) is not one boxmunge runs",
        "image with high ids": "has files owned by ids above 65535",
        "ipc host": "ipc cannot run on a remapped daemon",
    }
    (shop / "conf" / "app.ini").chmod(0o600)
    os.chown(uploads / "pg", 70000, 70000)
    subprocess.run(["setfacl", "-m", "u:1000:r", str(uploads / "root0600")], check=True)
    (uploads / "mnt").mkdir()
    subprocess.run(["mount", "-t", "tmpfs", "tmpfs", str(uploads / "mnt")], check=True)
    sb.sh("docker", "run", "-d", "--name", "bm-foreign", "--network", "none", BUSYBOX,
          "sleep", "3600")
    sb.sh("sh", "-c", f"printf 'FROM {BUSYBOX}\\nRUN echo x > /big && chown 70000 /big\\n' | "
                      f"docker build -q -t boxmunge.invalid/dind/high-ids -")
    sb.sh("docker", "run", "-d", "--name", "shop-ipc-1", "--ipc", "host", "--network", "none",
          "--label", "com.docker.compose.project=shop",
          "--label", "com.docker.compose.service=ipc", BUSYBOX, "sleep", "3600")
    try:
        report = _check(paths, images)
        assert not report.ok
        text = report.text()
        missing = [what for what, needle in planted.items() if needle not in text]
        assert not missing, f"{missing} not reported:\n{text}"
        # the command: one pass over all of it, a verdict last, exit 0 either way
        capsys.readouterr()
        assert run_check(paths) == 0
        out = capsys.readouterr().out.splitlines()
        assert out[-1].startswith("VERDICT: not ready") and not any(
            line.startswith("VERDICT") for line in out[:-1])
        assert all(needle in "\n".join(out) for needle in planted.values())
    finally:
        (shop / "conf" / "app.ini").chmod(0o644)
        subprocess.run(["umount", str(uploads / "mnt")], check=True)
        (uploads / "mnt").rmdir()
        os.chown(uploads / "pg", 70, 70)
        subprocess.run(["setfacl", "-b", str(uploads / "root0600")], check=True)
        sb.sh("docker", "rm", "-f", "-v", "bm-foreign", "shop-ipc-1")
        sb.sh("docker", "image", "rm", "boxmunge.invalid/dind/high-ids")
    report = _check(paths, images)
    assert report.ok, report.text()
    capsys.readouterr()
    assert run_check(paths) == 0
    assert capsys.readouterr().out.splitlines()[-1] == "VERDICT: ready"


def test_2_adopt_first_then_migrate(box, capsys) -> None:
    paths, images = box
    assert not _daemon_remapped()
    assert sb.deploy(paths, "anon", sb.anon_files("anon", named=False),
                     "2026-10-16T100000000000") == 0
    sb.in_container("anon", "keeper", "echo row > /held/x")
    assert "boxmunge data adopt anon keeper:/held <name>" in _check(paths, images).text()
    capsys.readouterr()
    assert sb.deploy(paths, "anon", sb.anon_files("anon", named=True),
                     "2026-10-16T100000000001") == 1
    err = capsys.readouterr().err
    assert "boxmunge data adopt anon keeper:/held held" in err
    assert "prod-deploy anon --abandon" in err  # the refused install is left open
    assert run_abandon("anon", paths) == 0
    assert run_data_adopt(paths, "anon", "keeper", "/held", "held") == 0
    assert sb.deploy(paths, "anon", sb.anon_files("anon", named=True),
                     "2026-10-16T100000000002") == 0
    assert sb.in_container("anon", "keeper", "cat /held/x").strip() == "row"
    # The adopted volume's old anonymous twin holds the data too, and nothing
    # uses it: it would be deleted by userns-commit, so the check refuses until
    # the operator has copied out what they need and removed it.
    report = _check(paths, images)
    dangling = re.findall(r"anonymous volume (\w+) holds \d+ bytes and no container uses it",
                          "\n".join(report.refusals))
    assert not report.ok and len(dangling) == 1, report.text()
    assert "docker volume rm " + dangling[0] in report.text()
    sb.sh("docker", "volume", "rm", dangling[0])
    report = _check(paths, images)
    assert report.ok, report.text()

    shop = paths.project_dir("shop")
    before = sb.owners(shop / "data" / "uploads")
    exports_owner = os.lstat(shop / "data" / "old-exports" / "dump.sql").st_uid
    ensure_identity()
    assert migration_in_progress(paths) is None
    timers = MarkedTimers(paths)
    j = _migrate(paths, images, timers)
    assert j.phase == "applied", (j.failed, j.items)
    # the marker was set before the timers stopped, refused a project command
    # (which prints why), and is cleared now the box runs again
    assert timers.at_stop == [(engine.FINISH, True)]
    assert timers.calls[0] == ("stop", "*") and timers.calls[-1][0] == "restore"
    assert migration_in_progress(paths) is None and not refuse_if_blocked("shop", paths)
    capsys.readouterr()
    assert run_check(paths) == 0
    assert f"VERDICT: already applied (offset {j.offset})" in capsys.readouterr().out
    assert _daemon_remapped() and uo.remap_offset(paths) == j.offset
    assert {k: v for k, v in j.items.items() if k.startswith("project:")} == {
        "project:anon": "up", "project:shop": "up"}
    assert sb.owners(shop / "data" / "uploads") == before
    assert os.lstat(shop / "data" / "old-exports" / "dump.sql").st_uid == exports_owner
    assert sb.psql("shop", "select v from t") == "42"
    assert sb.through_caddy("shop.localhost", "/pg") == (200, "b\n")
    assert sb.in_container("anon", "keeper", "cat /held/x").strip() == "row"
    assert sb.sh("docker", "inspect", "-f", "{{.HostConfig.UsernsMode}}",
                 "boxmunge-system").strip() == "host"
    # pg_dump in the remapped db, age in the host-namespace system container
    snapshots = len(list_snapshots(paths, "shop"))
    assert run_backup("shop", paths) == 0
    assert len(list_snapshots(paths, "shop")) == snapshots + 1


def test_3_soak_then_rollback_keeps_everything(box, alerts) -> None:
    paths, images = box
    assert load_journal(paths).phase == "applied"
    assert sb.deploy(paths, "soak", sb.shop_files("soak"), "2026-10-16T120000000000") == 0
    sb.wait_for_db("soak")
    sb.psql("soak", "create table t (v int); insert into t values (7)")
    sb.psql("shop", "insert into t values (43)")
    uploads = paths.project_dir("shop") / "data" / "uploads"
    sb.in_container("shop", "web", "echo new > /uploads/written-during-soak")
    sb.sh("docker", "pull", "-q", "alpine:3.21")
    timers = MarkedTimers(paths)
    j = _rollback(paths, images, timers)
    assert j.phase == "rolled-back", (j.failed, j.items)
    assert timers.at_stop == [("userns-rollback", True)]
    assert migration_in_progress(paths) is None and not refuse_if_blocked("shop", paths)
    assert alerts == ["userns migration rolled back"]
    assert not _daemon_remapped() and uo.recorded_offset(paths) is None
    assert sb.psql("shop", "select count(*) from t") == "2"
    assert sb.psql("soak", "select v from t") == "7"
    assert sb.sh("docker", "image", "inspect", "-f", "{{.Id}}", "alpine:3.21").strip()
    labels = json.loads(sb.sh("docker", "volume", "inspect", "-f", "{{json .Labels}}",
                              "shop_pgdata"))
    assert labels["com.docker.compose.project"] == "shop"
    seen = sb.owners(uploads)
    assert seen["./pg"][:2] == (70, 70) and seen["./sub"] == (999, 1000, 0o2770)
    assert seen["./suid"] == (999, 999, 0o4755)
    assert seen["./written-during-soak"][:2] == (10001, 10001)
    assert sb.through_caddy("soak.localhost", "/written-during-soak")[0] == 404
    assert sb.through_caddy("shop.localhost", "/written-during-soak") == (200, "new\n")


def test_4_migrate_again_and_commit(box, alerts) -> None:
    paths, images = box
    assert load_journal(paths).phase == "rolled-back"
    assert run_project_delete("soak", paths, yes=True, force=True) == 0
    j = _migrate(paths, images)
    assert j.phase == "applied", (j.failed, j.items)
    prior = j.prior_store
    assert Path(prior["store_root"]).is_dir()
    committed = commit(paths, now=datetime.fromisoformat(j.applied_at) + timedelta(hours=49),
                       images_dir=images)
    assert committed.phase == "committed" and load_journal(paths).phase == "committed"
    assert alerts == ["userns migration committed"]
    assert not Path(prior["store_root"]).exists() and not images.exists()
    assert sb.psql("shop", "select count(*) from t") == "2"
    assert sb.through_caddy("shop.localhost", "/pg") == (200, "b\n")
    assert run_backup("shop", paths) == 0
