# SPDX-License-Identifier: Apache-2.0
"""Production mounts its own copy of the release code it bind-mounts."""
from __future__ import annotations

import threading
from pathlib import Path

from boxmunge.live_mounts import LIVE_MOUNTS, LiveMounts, plan_live_mounts, sync_live_mounts


def _model(release: Path, *volumes, configs=None) -> dict:
    return {"services": {"web": {"image": "x", "volumes": list(volumes)}},
            "configs": configs or {}}


def test_code_mounts_are_repointed_and_data_is_not(tmp_path: Path) -> None:
    release = tmp_path / "release"
    plan = plan_live_mounts(_model(
        release,
        {"type": "bind", "source": str(release / "appconfig"), "target": "/etc/app",
         "read_only": True},
        "./site.conf:/etc/site.conf:ro",
        {"type": "bind", "source": str(release / "uploads"), "target": "/uploads"},
        {"type": "bind", "source": str(release / "data/db"), "target": "/db", "read_only": True},
        {"type": "bind", "source": str(release), "target": "/all", "read_only": True},
        {"type": "bind", "source": "/srv/elsewhere", "target": "/x", "read_only": True},
        {"type": "volume", "source": "cache", "target": "/cache"},
    ), release, {"data", "uploads"})
    assert plan.entries == {"appconfig", "site.conf"}
    assert plan.pinned == {"appconfig", "site.conf"}
    assert plan.volumes == {"web": [
        {"type": "bind", "source": f"./{LIVE_MOUNTS}/appconfig", "target": "/etc/app",
         "read_only": True},
        {"type": "bind", "source": f"./{LIVE_MOUNTS}/site.conf", "target": "/etc/site.conf",
         "read_only": True},
    ]}


def test_config_and_secret_files_of_release_code_are_repointed(tmp_path: Path) -> None:
    release = tmp_path / "release"
    plan = plan_live_mounts(_model(release, configs={
        "nginx": {"file": str(release / "conf" / "nginx.conf")},
        "box": {"file": str(release / "secrets.env")},
    }), release, {"secrets.env"})
    assert plan.files == {"configs": {"nginx": {"file": f"./{LIVE_MOUNTS}/conf/nginx.conf"}}}
    assert plan.entries == {"conf"}


def _sync(project: Path, release: Path, entries: set[str], pinned: set[str] = frozenset()):
    sync_live_mounts(project, release, LiveMounts(entries=frozenset(entries),
                                                  pinned=frozenset(pinned)))


def test_sync_mirrors_the_release_keeping_mounted_inodes(tmp_path: Path) -> None:
    release, project = tmp_path / "release", tmp_path / "project"
    (release / "appconfig" / "sub").mkdir(parents=True)
    (release / "appconfig" / "settings").write_text("v1")
    (release / "appconfig" / "same").write_text("same")
    (release / "site.conf").write_text("v1")
    _sync(project, release, {"appconfig", "site.conf", "absent"}, {"appconfig", "site.conf"})
    live = project / LIVE_MOUNTS
    inode = {p: (live / p).stat().st_ino for p in ("appconfig", "appconfig/sub",
                                                    "appconfig/same", "site.conf")}
    (live / "appconfig" / "stale").write_text("x")
    (live / "appconfig" / "evil").symlink_to(tmp_path)

    (release / "appconfig" / "settings").write_text("v2")
    (release / "site.conf").write_text("v2")
    _sync(project, release, {"appconfig", "site.conf"}, {"appconfig", "site.conf"})
    # Directory mounts and single-file mounts keep their inode; an
    # unchanged file is not rewritten.
    assert {p: (live / p).stat().st_ino for p in inode} == inode
    assert sorted(p.name for p in (live / "appconfig").iterdir()) == ["same", "settings", "sub"]
    assert (live / "appconfig" / "settings").read_text() == "v2"
    assert (live / "site.conf").read_text() == "v2"
    assert not (live / "absent").exists()  # no longer mounted
    assert tmp_path.exists()  # the planted link was removed, not followed


def test_no_path_is_missing_while_production_reads_it(tmp_path: Path) -> None:
    """Review of PR #65: a reader saw the config vanish during a refresh."""
    release, project = tmp_path / "release", tmp_path / "project"
    (release / "appconfig").mkdir(parents=True)
    for name in ("a.conf", "b.conf"):
        (release / "appconfig" / name).write_text("x" * 5000)
    (release / "site.conf").write_text("v0")
    _sync(project, release, {"appconfig", "site.conf"}, {"appconfig", "site.conf"})
    live = project / LIVE_MOUNTS
    watched = [live / "appconfig" / "a.conf", live / "appconfig" / "b.conf", live / "site.conf"]
    missing, stop = [], threading.Event()

    def read() -> None:
        while not stop.is_set():
            for path in watched:
                try:
                    path.read_bytes()
                except FileNotFoundError:
                    missing.append(path)

    reader = threading.Thread(target=read)
    reader.start()
    try:
        for i in range(200):
            (release / "appconfig" / "a.conf").write_text(str(i) * 5000)
            (release / "site.conf").write_text(f"v{i}")
            _sync(project, release, {"appconfig", "site.conf"}, {"appconfig", "site.conf"})
    finally:
        stop.set()
        reader.join()
    assert missing == []
    assert (live / "site.conf").read_text() == "v199"


def test_an_entry_the_release_lacks_is_an_empty_directory(tmp_path: Path) -> None:
    """As Docker creates a missing short-syntax source."""
    _sync(tmp_path / "project", tmp_path / "release", {"appconfig"})
    live = tmp_path / "project" / LIVE_MOUNTS / "appconfig"
    assert live.is_dir() and not any(live.iterdir())


def test_a_planted_link_is_replaced_never_written_through(tmp_path: Path) -> None:
    release, project = tmp_path / "release", tmp_path / "project"
    release.mkdir()
    (release / "site.conf").write_text("release")
    victim = tmp_path / "victim"
    victim.write_text("untouched")
    (project / LIVE_MOUNTS).mkdir(parents=True)
    (project / LIVE_MOUNTS / "site.conf").symlink_to(victim)
    _sync(project, release, {"site.conf"}, {"site.conf"})
    assert victim.read_text() == "untouched"
    copy = project / LIVE_MOUNTS / "site.conf"
    assert not copy.is_symlink() and copy.read_text() == "release"
