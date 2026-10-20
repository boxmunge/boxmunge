"""userns-commit on the containerd store kept by the system containerd.

Docker's packages run containerd as its own service, shared by the old and
the remapped daemon, so the commit empties the old daemon's namespace in it
rather than deleting a root (dind's dockerd otherwise runs its own
containerd, which the other modules use). The box is migrated, deployed
during the soak, rolled back, deployed again on the old daemon, migrated
again and committed, as tests/vm/vm-userns.py does on a VM. The deploy on
the old daemon replaces a container, and dockerd's release of its rootfs
leaves the container's snapshots in their image's list of children, which
no snapshot can be removed by name past.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from boxmunge.paths import BoxPaths
from boxmunge.userns import commit as commit_mod
from boxmunge.userns.commit import commit
from boxmunge.userns.engine import migrate
from boxmunge.userns.journal import load_journal
from boxmunge.userns.rollback import rollback
from boxmunge.userns.switch import MigrationError
from tests.integration.userns import migration_box as mb
from tests.integration.userns.conftest import USERNS_DIND
from tests.integration.userns.crashsweep import crash_before
from tests.integration.userns.dockerd import (
    FakeTimers, ProcessDaemon, _wait, prior_daemon_json, write_daemon_json,
)

# run-in-dind.sh installs it on the containerd prior store's entry of the matrix.
CONTAINERD = os.environ.get("BOXMUNGE_DIND_SYSTEM_CONTAINERD", "")
pytestmark = [*USERNS_DIND, pytest.mark.skipif(
    not CONTAINERD, reason="needs BOXMUNGE_DIND_SYSTEM_CONTAINERD (the containerd prior "
    "store's dind job)")]

SOCK = "/run/containerd/containerd.sock"
ROOT = Path("/var/lib/containerd")
# On the dind volume: overlayfs cannot stack on the container's own rootfs.
STORE = Path("/var/lib/docker/boxmunge-system-containerd")
LOG = Path("/var/log/containerd-system.log")


def _ctr(namespace: str, *args: str) -> str:
    return subprocess.run(["ctr", "--address", SOCK, "-n", namespace, *args],
                          capture_output=True, text=True, check=True).stdout


def _clean_daemon() -> None:
    for name in mb.docker("ps", "-aq").stdout.split():
        mb.docker("rm", "-f", "-v", name)
    mb.docker("volume", "prune", "-af")
    mb.docker("network", "rm", "boxmunge-proxy", check=False)


def _unmount_store() -> None:
    """The bind mount, after anything still mounted from the store (most
    nested first); what holds it, when it will not go."""
    lines = Path("/proc/mounts").read_text().splitlines()
    held = [line for line in lines if str(ROOT) in line or str(STORE) in line]
    for point in sorted({line.split()[1] for line in held}, key=len, reverse=True):
        if subprocess.run(["umount", point], capture_output=True).returncode != 0:
            raise AssertionError(f"cannot unmount {point}; mounts on the store:\n"
                                 + "\n".join(held))


@pytest.fixture(scope="module")
def system_containerd():
    daemon = ProcessDaemon()
    daemon.stop()
    # dockerd's own containerd root, from the earlier modules, stays: the
    # migration asks the daemon which containerd it uses.
    assert Path("/var/lib/docker/containerd/daemon").is_dir()
    STORE.mkdir()
    ROOT.mkdir(exist_ok=True)
    subprocess.run(["mount", "--bind", str(STORE), str(ROOT)], check=True)
    with LOG.open("ab") as log:
        containerd = subprocess.Popen([CONTAINERD], stdout=log, stderr=subprocess.STDOUT,
                                      start_new_session=True)
    _wait(lambda: subprocess.run(["ctr", "--address", SOCK, "version"],
                                 capture_output=True).returncode == 0, "containerd to answer")
    write_daemon_json({**prior_daemon_json(), "containerd": SOCK})
    daemon.start()
    try:
        yield
    finally:
        # Whichever daemon.json a failed test left, both daemons' stores are
        # emptied of the box (the remapped root outlives a commit, and later
        # modules switch to it), then the daemon goes back to its own.
        daemon.stop()
        daemon.start()
        _clean_daemon()
        daemon.stop()
        write_daemon_json({**prior_daemon_json(), "containerd": SOCK})
        daemon.start()
        _clean_daemon()
        daemon.stop()
        containerd.terminate()
        containerd.wait(timeout=60)
        _unmount_store()
        shutil.rmtree(STORE)
        write_daemon_json(prior_daemon_json())
        daemon.start()


@pytest.fixture(scope="module")
def box(tmp_path_factory, system_containerd):
    root = tmp_path_factory.mktemp("system-containerd") / "boxmunge"
    for sub in ("config", "projects", "state/deploy", "state/health", "logs", "caddy/sites",
                "system", "upgrade-state"):
        (root / sub).mkdir(parents=True)
    paths = BoxPaths(root=root)
    with pytest.MonkeyPatch.context() as mp:
        mb.stand_ins(mp)
        mb.make_box(paths)
        yield paths, root.parent / "img"


def _migrate(paths, images) -> None:
    migrate(paths, daemon=ProcessDaemon(), timers=FakeTimers(), images_dir=images)


def _deploy(paths) -> None:
    """A deploy that replaces the project's container."""
    mb.docker("compose", "-p", mb.PROJECT, "up", "-d", "--force-recreate", "--no-build",
              "--pull", "never", cwd=paths.project_dir(mb.PROJECT))


def _empty(namespace: str) -> dict[str, list[str]]:
    held = {kind: _ctr(namespace, kind, "ls", "-q").split()
            for kind in ("containers", "images", "leases", "content")}
    held["snapshots"] = _ctr(namespace, "snapshots", "--snapshotter", "overlayfs",
                             "ls").splitlines()[1:]
    return {kind: keys for kind, keys in held.items() if keys}


def _killed_before_collecting(paths, now, images) -> None:
    """In crash_before's child: the commit dies once the old namespace's
    leases and images are gone, before containerd collects what they held."""
    commit_mod._collect = lambda prior: os._exit(137)
    commit(paths, now=now, images_dir=images)


def test_commit_after_a_rollback_and_a_second_migration_empties_the_old_namespace(box) -> None:
    paths, images = box
    before = mb.view()
    _migrate(paths, images)
    _deploy(paths)  # during the soak, on the remapped daemon
    rollback(paths, daemon=ProcessDaemon(), timers=FakeTimers(), images_dir=images)
    _deploy(paths)  # the box runs on, on the old daemon
    assert not mb.daemon_remapped() and mb.view() == before
    _migrate(paths, images)
    j = load_journal(paths)
    assert j.prior_store["managed"] is False and j.prior_store["store_root"] == str(ROOT)
    assert j.prior_store["containerd"] == {"address": SOCK, "namespace": "moby"}
    remapped = f"moby-{j.offset}.{j.offset}"
    theirs = {k: _ctr(remapped, k, "ls", "-q") for k in ("containers", "leases")}
    soaked = datetime.fromisoformat(j.applied_at) + timedelta(hours=49)

    assert crash_before(10**9, lambda: _killed_before_collecting(paths, soaked, images)) == 137
    assert load_journal(paths).phase == "applied"
    assert not _ctr("moby", "images", "ls", "-q").strip()
    commit(paths, now=soaked, images_dir=images)  # resumed

    assert load_journal(paths).phase == "committed" and _empty("moby") == {}
    assert {k: _ctr(remapped, k, "ls", "-q") for k in ("containers", "leases")} == theirs
    assert mb.daemon_remapped() and mb.view() == before
    with pytest.raises(MigrationError, match="committed"):
        rollback(paths, daemon=ProcessDaemon(), timers=FakeTimers(), images_dir=images)
