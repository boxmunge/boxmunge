"""Rollback restores the code and the data of the release before the last
deploy, or refuses with the reason (audit C-02).

Previously a bundle rollback restored the data snapshot but "redeployed" the
bad code still on disk and reported success.
"""
from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import patch

import pytest

from boxmunge.backup import BackupKind
from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.rollback import (
    RollbackUnavailable, find_rollback_target, run_rollback,
)
from boxmunge.project_registry import add_project
from boxmunge.state import read_state, write_state

from tests.bundle_helpers import HOSTILE_COMPOSE, manifest_text, place_bundle, tree_snapshot

V1 = "2026-10-13T090000000000"
V2 = "2026-10-13T100000000000"


@contextmanager
def _docker():
    with patch("boxmunge.compose_guard.compose_up") as up, \
            patch("boxmunge.commands.deploy.caddy_reload"):
        yield up


def _deploy(paths, ts, files=None, backup="none") -> None:
    files = {"manifest.yml": manifest_text(backup=backup), **(files or {})}
    place_bundle(paths, timestamp=ts, files=files)
    with _docker():
        assert run_deploy("myapp", paths) == 0


@pytest.fixture
def two_releases(paths):
    add_project("myapp", paths)
    _deploy(paths, V1, {"VERSION": "v1-good\n", "old-only.txt": "v1\n"})
    _deploy(paths, V2, {"VERSION": "v2-bad\n"})
    return paths.project_dir("myapp")


class TestDeployKeepsThePreviousRelease:
    def test_refs_name_the_bundles(self, paths, two_releases) -> None:
        state = read_state(paths.project_deploy_state("myapp"))
        assert state["current_ref"] == f"myapp-{V2}"
        assert state["history"][0]["ref"] == f"myapp-{V1}"

    def test_release_tree_is_exactly_the_bundle(self, two_releases) -> None:
        assert (two_releases / "VERSION").read_text() == "v2-bad\n"
        assert not (two_releases / "old-only.txt").exists()

    def test_previous_release_is_the_replaced_code(self, paths, two_releases) -> None:
        target = find_rollback_target(paths, "myapp")
        assert target.ref == f"myapp-{V1}"
        assert (target.tree / "VERSION").read_text() == "v1-good\n"
        assert (target.tree / "old-only.txt").exists()
        assert target.snapshot == ""


class TestRollbackRestoresCode:
    def test_rollback_puts_back_the_previous_code(self, paths, two_releases) -> None:
        with _docker() as up:
            assert run_rollback("myapp", paths, yes=True) == 0
        up.assert_called_once()
        assert (two_releases / "VERSION").read_text() == "v1-good\n"
        assert (two_releases / "old-only.txt").read_text() == "v1\n"
        state = read_state(paths.project_deploy_state("myapp"))
        assert state["current_ref"] == f"myapp-{V1}"

    def test_box_state_survives_rollback(self, paths, two_releases) -> None:
        (two_releases / "secrets.env").write_text("KEY=live\n")
        (two_releases / "data" / "app.db").write_text("LIVE")
        with _docker():
            assert run_rollback("myapp", paths, yes=True) == 0
        assert (two_releases / "secrets.env").read_text() == "KEY=live\n"
        assert (two_releases / "data" / "app.db").read_text() == "LIVE"

    def test_second_rollback_refuses(self, paths, two_releases, capsys) -> None:
        with _docker():
            assert run_rollback("myapp", paths, yes=True) == 0
            assert run_rollback("myapp", paths, yes=True) == 1
        assert "no previous release" in capsys.readouterr().err

    def test_rollback_never_picks_up_an_inbox_bundle(self, paths, two_releases) -> None:
        place_bundle(paths, timestamp="2026-10-13T110000000000",
                     files={"VERSION": "v3-unreviewed\n"})
        with _docker():
            assert run_rollback("myapp", paths, yes=True) == 0
        assert (two_releases / "VERSION").read_text() == "v1-good\n"

    def test_a_previous_release_with_a_new_manifest_error_warns_and_rolls_back(
        self, paths, two_releases, capsys,
    ) -> None:
        previous = find_rollback_target(paths, "myapp").tree
        manifest = previous / "manifest.yml"
        manifest.write_text(manifest.read_text().replace(
            "    port: 8080\n", "    port: 8080\n    internal: true\n"))
        with _docker():
            assert run_rollback("myapp", paths, yes=True) == 0
        assert "internal: true but has routes" in capsys.readouterr().out
        assert (two_releases / "VERSION").read_text() == "v1-good\n"

    def test_previous_release_failing_validation_changes_nothing(
        self, paths, two_releases,
    ) -> None:
        previous = find_rollback_target(paths, "myapp").tree
        (previous / "compose.yml").write_text(HOSTILE_COMPOSE)
        before = tree_snapshot(two_releases)
        with _docker() as up:
            assert run_rollback("myapp", paths, yes=True) == 3
        up.assert_not_called()
        assert tree_snapshot(two_releases) == before


class TestRollbackRestoresData:
    @staticmethod
    def _fake_backup(paths):
        counter = iter(range(100))

        def backup_locked(project_name, paths_, kind=None, manifest=None):
            assert kind is BackupKind.PREDEPLOY
            n = next(counter)
            snap = paths_.project_backups(project_name) / f"{project_name}-snap{n}.tar.gz.age"
            snap.parent.mkdir(parents=True, exist_ok=True)
            snap.write_text(f"snapshot {n}")
            return 0
        return backup_locked

    def test_code_and_matching_snapshot_restored(self, paths) -> None:
        add_project("myapp", paths)
        with patch("boxmunge.commands.backup_cmd.backup_locked", self._fake_backup(paths)):
            _deploy(paths, V1, {"VERSION": "v1\n"}, backup="postgres")
            _deploy(paths, V2, {"VERSION": "v2\n"}, backup="postgres")
        pdir = paths.project_dir("myapp")
        # The snapshot taken just before v2 replaced v1 pairs with v1's code.
        target = find_rollback_target(paths, "myapp")
        assert target.snapshot == "myapp-snap0.tar.gz.age"

        restored = {}

        def fake_restore(project_name, paths_, snapshot=None, txn=None):
            restored["snapshot"] = snapshot
            restored["code"] = (pdir / "VERSION").read_text()
            return 0

        with patch("boxmunge.commands.rollback.restore_locked", fake_restore), _docker():
            assert run_rollback("myapp", paths, yes=True) == 0
        # Data is restored with the previous release's code already in place.
        assert restored == {"snapshot": "myapp-snap0.tar.gz.age", "code": "v1\n"}
        assert (pdir / "VERSION").read_text() == "v1\n"

    def test_refuses_when_backups_exist_but_no_snapshot_was_taken(
        self, paths, capsys,
    ) -> None:
        add_project("myapp", paths)
        with patch("boxmunge.commands.backup_cmd.backup_locked", return_value=1):
            _deploy(paths, V1, {"VERSION": "v1\n"}, backup="postgres")
            _deploy(paths, V2, {"VERSION": "v2\n"}, backup="postgres")
        pdir = paths.project_dir("myapp")
        before = tree_snapshot(pdir)
        assert run_rollback("myapp", paths, yes=True) == 1
        assert "no pre-deploy data snapshot" in capsys.readouterr().err
        assert tree_snapshot(pdir) == before


class TestRefusals:
    def test_never_deployed(self, paths) -> None:
        with pytest.raises(RollbackUnavailable, match="not been deployed"):
            find_rollback_target(paths, "myapp")

    def test_first_deploy_has_no_previous_release(self, paths, capsys) -> None:
        add_project("myapp", paths)
        _deploy(paths, V1)
        assert run_rollback("myapp", paths, yes=True) == 1
        assert "no previous release" in capsys.readouterr().err

    def test_repo_project_needs_history(self, paths) -> None:
        pdir = paths.project_dir("myapp")
        (pdir / "repo").mkdir(parents=True)
        (pdir / "manifest.yml").write_text(manifest_text())
        write_state(paths.project_deploy_state("myapp"), {
            "current_ref": "abc123", "pre_deploy_snapshot": "", "history": [],
        })
        with pytest.raises(RollbackUnavailable, match="no previous deploy"):
            find_rollback_target(paths, "myapp")

    def test_repo_project_target(self, paths, tmp_path) -> None:
        from tests.git_helpers import commit, git, origin_with
        origin, work = origin_with(tmp_path, {"manifest.yml": manifest_text()})
        previous = git("rev-parse", "HEAD", cwd=work)
        current = commit(work, {"f": "x"}, "current")
        pdir = paths.project_dir("myapp")
        pdir.mkdir(parents=True)
        git("clone", "-q", str(origin), str(pdir / "repo"), cwd=tmp_path)
        (pdir / "manifest.yml").symlink_to(pdir / "repo" / "manifest.yml")
        write_state(paths.project_deploy_state("myapp"), {
            "current_ref": current, "pre_deploy_snapshot": "",
            "history": [{"ref": previous[:7]}],   # 0.10.1 recorded short SHAs
        })
        target = find_rollback_target(paths, "myapp")
        assert target.ref == previous
        assert target.tree is None


class TestExplicitRef:
    def test_unknown_ref_is_an_error_not_a_redeploy(self, paths, two_releases, capsys) -> None:
        with _docker() as up:
            assert run_deploy("myapp", paths, ref="2026-01-01") == 1
        up.assert_not_called()
        assert "No bundle" in capsys.readouterr().err
