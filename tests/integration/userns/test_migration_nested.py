"""A data tree inside another: a service mounts ./storage/sub read-write and
data-dirs records storage. The migration shifts storage once, sub with it,
and the rollback puts every owner back."""
from __future__ import annotations

import os


from boxmunge.paths import BoxPaths
from boxmunge.userns.engine import migrate
from boxmunge.userns.journal import load_journal
from boxmunge.userns.rollback import rollback
from tests.integration.userns import migration_box as mb
from tests.integration.userns.conftest import USERNS_DIND
from tests.integration.userns.dockerd import FakeTimers, ProcessDaemon

pytestmark = USERNS_DIND


def test_a_tree_inside_a_recorded_one_is_shifted_once(tmp_path_factory, monkeypatch) -> None:
    root = tmp_path_factory.mktemp("nest") / "boxmunge"
    for sub in ("config", "projects", "state/deploy", "state/health", "logs", "caddy/sites",
                "system", "upgrade-state"):
        (root / sub).mkdir(parents=True)
    paths = BoxPaths(root=root)
    monkeypatch.setattr(mb, "COMPOSE", mb.COMPOSE.replace(
        "      - ./conf:/conf:ro\n", "      - ./conf:/conf:ro\n      - ./storage/sub:/sub\n"))
    mb.stand_ins(monkeypatch)
    sub = paths.project_dir(mb.PROJECT) / "storage" / "sub"
    sub.mkdir(parents=True)
    (sub / "row").write_text("1")
    os.chown(sub / "row", 70, 70)
    releases = paths.project_dir(mb.PROJECT) / ".releases"
    releases.mkdir()
    (releases / "data-dirs.json").write_text('{"version": 1, "data_dirs": ["storage"]}')
    mb.make_box(paths)
    img = root.parent / "img"
    before = (mb.view(), mb.host_owners(paths))
    try:
        migrate(paths, daemon=ProcessDaemon(), timers=FakeTimers(), images_dir=img)
        outcome = None
        s = load_journal(paths).offset
        assert os.lstat(sub / "row").st_uid == s + 70  # shifted once, with storage
    except Exception as e:  # rolled back below either way, then reported
        outcome = e
    rollback(paths, daemon=ProcessDaemon(), timers=FakeTimers(), images_dir=img)
    assert (mb.view(), mb.host_owners(paths)) == before
    assert os.lstat(sub / "row").st_uid == 70
    mb.docker("compose", "-p", mb.PROJECT, "down", "-v", cwd=paths.project_dir(mb.PROJECT), check=False)
    mb.docker("network", "rm", "boxmunge-proxy", check=False)
    assert outcome is None, f"{outcome} (journal: {load_journal(paths).failed})"
