"""project-delete fails loudly on teardown errors and clears all per-project state.

Audit D-09 / C-18: a failed ``compose down`` was swallowed and the compose
files deleted, orphaning the containers; pause and quarantine markers and
other per-project state survived, so re-creating the name came up paused or
quarantined.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from boxmunge.docker import DockerError
from boxmunge.lifecycle import is_blocked
from boxmunge.paths import BoxPaths
from boxmunge.project_alerts import alert_state
from boxmunge.legacy_stage import legacy_staging_state
from boxmunge.project_registry import add_project, is_registered
from boxmunge.state import write_state

NAME = "myapp"


def _state_files(paths: BoxPaths) -> list[Path]:
    return [
        paths.project_health_state(NAME),
        paths.project_deploy_state(NAME),
        paths.project_paused_state(NAME),
        paths.project_quarantine_state(NAME),
        paths.project_scan_state(NAME),
        legacy_staging_state(paths, NAME),
        paths.container_update_target_state(NAME),
        alert_state(paths, NAME, "manifest-schema"),
        alert_state(paths, NAME, "git-layout"),
        paths.project_caddy_site(NAME),
        paths.project_staging_caddy_site(NAME),
    ]


@pytest.fixture
def box(paths: BoxPaths) -> BoxPaths:
    paths.config_file.write_text("hostname: t\nadmin_email: a@b\n")
    pdir = paths.project_dir(NAME)
    pdir.mkdir(parents=True)
    (pdir / "manifest.yml").write_text(yaml.dump({
        "schema_version": 1, "id": "01TEST", "project": NAME, "source": "bundle",
        "hosts": [f"{NAME}.test"],
        "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
    }))
    (pdir / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
    (pdir / "compose.boxmunge.yml").write_text("services: {}\n")
    (pdir / "compose.boxmunge-staging.yml").write_text("services: {}\n")
    for f in _state_files(paths):
        if f.suffix == ".conf":
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text("# site\n")
        else:
            write_state(f, {"x": 1})
    add_project(NAME, paths)
    return paths


def _delete(paths: BoxPaths, down, reload_=None, **kw) -> int:
    from boxmunge.commands import project_delete_cmd
    with patch.object(project_delete_cmd, "compose_down", down), \
         patch.object(project_delete_cmd, "caddy_reload", reload_ or MagicMock()):
        return project_delete_cmd.run_project_delete(NAME, paths, yes=True, **kw)


class TestTeardownFailure:
    @pytest.mark.parametrize("failing", ["prod", "staging"])
    def test_failed_teardown_deletes_nothing(self, box, failing, capsys):
        def down(project_dir, compose_files=None, project_name=None, remove_orphans=False):
            is_staging = project_name == f"{NAME}-staging"
            if (failing == "staging") == is_staging:
                raise DockerError("daemon unreachable")

        reload_ = MagicMock()
        assert _delete(box, down, reload_) == 1
        err = capsys.readouterr().err
        assert "daemon unreachable" in err and "--force" in err
        pdir = box.project_dir(NAME)
        assert (pdir / "compose.yml").exists(), "compose files kept for the retry"
        assert (pdir / "compose.boxmunge.yml").exists()
        assert all(f.exists() for f in _state_files(box))
        assert is_registered(NAME, box)
        reload_.assert_not_called()

    def test_force_deletes_despite_teardown_failure(self, box, capsys):
        down = MagicMock(side_effect=DockerError("daemon unreachable"))
        assert _delete(box, down, force=True) == 0
        assert not box.project_dir(NAME).exists()
        assert "WARN" in capsys.readouterr().out


class TestCompleteRemoval:
    def test_removes_every_per_project_file_and_staging(self, box):
        down = MagicMock()
        assert _delete(box, down) == 0
        assert not box.project_dir(NAME).exists()
        leftover = [str(f) for f in _state_files(box) if f.exists()]
        assert leftover == []
        assert not box.project_alerts_dir(NAME).exists()
        assert not is_registered(NAME, box)
        staging = [c for c in down.call_args_list
                   if c.kwargs.get("project_name") == f"{NAME}-staging"]
        assert len(staging) == 1

    def test_recreated_name_is_not_paused_or_quarantined(self, box):
        assert is_blocked(NAME, box) is not None  # markers present before
        assert _delete(box, MagicMock()) == 0
        add_project(NAME, box)
        assert is_blocked(NAME, box) is None

    def test_caddy_reload_failure_is_reported(self, box, capsys):
        reload_ = MagicMock(side_effect=DockerError("caddy validate failed"))
        assert _delete(box, MagicMock(), reload_) == 1
        assert not box.project_dir(NAME).exists()
        assert "caddy validate failed" in capsys.readouterr().err


def test_bad_registry_line_neither_blocks_the_delete_nor_is_dropped(box):
    registry = box.state / "projects.txt"
    registry.write_text(f"{NAME}\nold-staging\n")
    assert _delete(box, MagicMock()) == 0
    assert not box.project_dir(NAME).exists()
    assert registry.read_text() == "old-staging\n"


class TestContainerOwnedData:
    """Data a container wrote belongs to its user (S+N on a remapped box),
    which deploy cannot remove; the helper empties it first."""

    def test_is_emptied_by_the_helper_before_the_tree_goes(self, box, monkeypatch):
        from boxmunge.commands import project_delete_cmd as pd
        pdir = box.project_dir(NAME)
        (pdir / "pgdata").mkdir()
        (pdir / "pgdata" / "PG_VERSION").write_text("16")
        seen = []
        monkeypatch.setattr(pd, "container_owned_dirs", lambda root: [root / "pgdata"])

        def empty(label, root, rel):
            seen.append((label, root, rel, sorted(p.name for p in (root / rel).iterdir())))
            (root / rel / "PG_VERSION").unlink()
        monkeypatch.setattr(pd, "empty_under", empty)
        assert _delete(box, MagicMock()) == 0
        assert seen == [("myapp-delete", pdir, Path("pgdata"), ["PG_VERSION"])]
        assert not pdir.exists()

    def test_a_failed_helper_keeps_the_project_for_a_retry(self, box, monkeypatch, capsys):
        from boxmunge.commands import project_delete_cmd as pd
        pdir = box.project_dir(NAME)
        monkeypatch.setattr(pd, "container_owned_dirs", lambda root: [root / "pgdata"])

        def empty(label, root, rel):
            raise DockerError("rm: can't remove '/p/pgdata/f': Permission denied")
        monkeypatch.setattr(pd, "empty_under", empty)
        assert _delete(box, MagicMock()) == 1
        assert pdir.exists() and is_registered(NAME, box)
        err = capsys.readouterr().err
        assert "Permission denied" in err and "project-delete" in err

    def test_teardown_removes_orphans_too(self, box):
        down = MagicMock()
        assert _delete(box, down) == 0
        assert down.call_count == 2
        assert all(c.kwargs.get("remove_orphans") is True for c in down.call_args_list)


def _no_helper(monkeypatch):
    from boxmunge.commands import project_delete_cmd as pd
    monkeypatch.setattr(pd, "container_owned_dirs", lambda root: [root / "pgdata"])
    monkeypatch.setattr(pd, "empty_under", lambda *a: pytest.fail("helper used"))


def _refused(box, capsys, rc, name):
    assert rc == 1
    assert box.project_dir(NAME).exists() and is_registered(NAME, box)
    err = capsys.readouterr().err
    assert name in err and "still exist" in err


def test_a_one_off_survivor_is_refused(box, monkeypatch, capsys, fake_containers):
    """`compose down` leaves `compose run` containers running."""
    _no_helper(monkeypatch)
    fake_containers.run(NAME, "db", "sha256:x", name="myapp-db-run-1a2b", oneoff=True)
    _refused(box, capsys, _delete(box, MagicMock()), "myapp-db-run-1a2b")


def test_a_retry_without_compose_files_is_refused_while_containers_exist(
        box, monkeypatch, capsys, fake_containers):
    """A retry after a partial forced delete runs no teardown at all."""
    _no_helper(monkeypatch)
    for f in ("compose.yml", "compose.boxmunge.yml", "compose.boxmunge-staging.yml"):
        (box.project_dir(NAME) / f).unlink()
    fake_containers.run(f"{NAME}-staging", "db", "sha256:x", running=False)
    down = MagicMock()
    _refused(box, capsys, _delete(box, down), "myapp-staging-db-1")
    down.assert_not_called()


def test_a_forced_delete_is_refused_while_containers_exist(box, monkeypatch, capsys,
                                                           fake_containers):
    from boxmunge.commands import project_delete_cmd as pd
    _no_helper(monkeypatch)
    monkeypatch.setattr(pd, "_teardown", lambda name, paths: ["production: boom"])
    monkeypatch.setattr(pd, "caddy_reload", lambda *a, **k: None)
    fake_containers.run(NAME, "db", "sha256:x")
    _refused(box, capsys, pd.delete_locked(NAME, box, force=True), "myapp-db-1")


def test_emptied_dirs_are_removed_even_when_unreadable(box, monkeypatch):
    """CI on Linux: an emptied 0700 directory of uid 999 cannot be listed by
    deploy, and rmtree lists every directory it removes; rmdir needs only
    the parent's write permission."""
    from boxmunge.commands import project_delete_cmd as pd
    pdir = box.project_dir(NAME)
    (pdir / "pgdata" / "base").mkdir(parents=True)
    monkeypatch.setattr(pd, "container_owned_dirs", lambda root: [root / "pgdata"])

    def empty(label, root, rel):
        (root / rel / "base").rmdir()
        (root / rel).chmod(0)  # as deploy sees 999's 0700 directory
    monkeypatch.setattr(pd, "empty_under", empty)
    try:
        assert _delete(box, MagicMock()) == 0
    finally:
        if (pdir / "pgdata").exists():
            (pdir / "pgdata").chmod(0o755)
    assert not pdir.exists()
