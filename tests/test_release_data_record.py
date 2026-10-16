"""A directory that once held data is never reclassified as release code.

Codebase review finding 02: release A bind-mounts ./uploads read-write,
release B drops the mount. The first install of B kept uploads/ (the
outgoing compose.yml still mounted it), but the next install found no
compose file mentioning it, treated it as stale code and deleted it.

The project now records every entry that has held data in
.releases/data-dirs.json; installs never remove, overwrite or copy a
recorded entry into a kept release, and say when one is no longer mounted.
"""
from __future__ import annotations

import json
import shutil
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge.bundle import BundleError
from boxmunge.release import ReleaseStateError, install_release, live_code_entries

MOUNTS_UPLOADS = ("services:\n  web:\n    image: nginx\n"
                  "    volumes: [\"./uploads:/uploads\"]\n")
NO_MOUNTS = "services:\n  web:\n    image: nginx\n"
MOUNTS_STATE_FILE = ("services:\n  web:\n    image: nginx\n"
                     "    volumes: [\"./state.json:/srv/state.json\"]\n")


def _release(root: Path, name: str, compose: str, files: dict[str, str] | None = None) -> Path:
    tree = root / name
    tree.mkdir()
    (tree / "manifest.yml").write_text("project: app\n")
    (tree / "compose.yml").write_text(compose)
    for rel, text in (files or {}).items():
        (tree / rel).parent.mkdir(parents=True, exist_ok=True)
        (tree / rel).write_text(text)
    return tree


def _record(project: Path) -> Path:
    return project / ".releases" / "data-dirs.json"


@pytest.fixture
def project(tmp_path: Path) -> Path:
    """A project live on release A, whose app has written to uploads/."""
    a = _release(tmp_path, "a", MOUNTS_UPLOADS)
    project = tmp_path / "project"
    project.mkdir()
    install_release(a, project)
    (project / "uploads").mkdir()
    (project / "uploads" / "photo.jpg").write_text("USER UPLOAD")
    return project


class TestRetiredMountKeepsItsData:
    def test_a_then_b_twice_then_a_again(self, tmp_path: Path, project: Path) -> None:
        b = _release(tmp_path, "b", NO_MOUNTS)
        a = tmp_path / "a"
        for tree in (b, b, a, b, a):
            install_release(tree, project)
            assert (project / "uploads" / "photo.jpg").read_text() == "USER UPLOAD"
        assert project / "uploads" not in live_code_entries(project, b)

    def test_retired_dir_is_not_copied_into_a_kept_release(
        self, tmp_path: Path, project: Path,
    ) -> None:
        b = _release(tmp_path, "b", NO_MOUNTS)
        install_release(b, project)
        assert "uploads" not in {e.name for e in live_code_entries(project, b)}

    def test_retiring_a_mount_warns_and_names_the_way_to_delete(
        self, tmp_path: Path, project: Path, capsys,
    ) -> None:
        b = _release(tmp_path, "b", NO_MOUNTS)
        assert install_release(b, project) == ["uploads"]
        out = capsys.readouterr().out
        assert "WARNING" in out and "uploads/" in out
        assert f"rm -rf {project / 'uploads'}" in out
        assert install_release(b, project) == ["uploads"]

    def test_mounted_data_is_not_reported(self, tmp_path: Path, project: Path) -> None:
        assert install_release(tmp_path / "a", project) == []

    def test_staging_copy_of_a_retired_dir_is_kept(
        self, tmp_path: Path, project: Path,
    ) -> None:
        (project / "uploads-staging").mkdir()
        (project / "uploads-staging" / "photo.jpg").write_text("STAGING COPY")
        b = _release(tmp_path, "b", NO_MOUNTS)
        install_release(b, project)
        install_release(b, project)
        assert (project / "uploads-staging" / "photo.jpg").exists()

    def test_release_shipping_content_for_a_retired_dir_is_refused(
        self, tmp_path: Path, project: Path,
    ) -> None:
        b = _release(tmp_path, "b", NO_MOUNTS)
        install_release(b, project)
        c = _release(tmp_path, "c", NO_MOUNTS, {"uploads/index.html": "CODE"})
        with pytest.raises(BundleError, match="uploads.*holds data"):
            install_release(c, project)
        assert (project / "uploads" / "photo.jpg").read_text() == "USER UPLOAD"
        assert not (project / "uploads" / "index.html").exists()

    def test_deleting_a_retired_dir_on_the_server_releases_its_name(
        self, tmp_path: Path, project: Path,
    ) -> None:
        """The operator's deliberate delete is what ends its life as data."""
        b = _release(tmp_path, "b", NO_MOUNTS)
        install_release(b, project)
        shutil.rmtree(project / "uploads")
        c = _release(tmp_path, "c", NO_MOUNTS, {"uploads/index.html": "CODE"})
        assert install_release(c, project) == []
        assert (project / "uploads" / "index.html").read_text() == "CODE"
        assert json.loads(_record(project).read_text())["data_dirs"] == []

    def test_staging_copy_keeps_the_name_reserved(
        self, tmp_path: Path, project: Path,
    ) -> None:
        """Deleting uploads/ alone leaves its data in uploads-staging/."""
        (project / "uploads-staging").mkdir()
        (project / "uploads-staging" / "photo.jpg").write_text("STAGING COPY")
        install_release(_release(tmp_path, "b", NO_MOUNTS), project)

        shutil.rmtree(project / "uploads")
        c = _release(tmp_path, "c", NO_MOUNTS, {"uploads/index.html": "CODE"})
        with pytest.raises(BundleError, match="uploads-staging"):
            install_release(c, project)
        assert (project / "uploads-staging" / "photo.jpg").exists()


class TestEmptyDataDirCanBecomeCode:
    RO = ("services:\n  web:\n    image: nginx\n"
          "    volumes: [\"./uploads:/uploads:ro\"]\n")

    def test_release_fills_an_empty_dir_it_now_mounts_read_only(
        self, tmp_path: Path,
    ) -> None:
        project = tmp_path / "project"
        project.mkdir()
        install_release(_release(tmp_path, "a", MOUNTS_UPLOADS), project)
        (project / "uploads").mkdir()  # created by Docker, never written
        for n, page in enumerate(("v1", "v2")):
            tree = _release(tmp_path, f"b{n}", self.RO, {"uploads/index.html": page})
            assert install_release(tree, project) == []
            assert (project / "uploads" / "index.html").read_text() == page
        assert json.loads(_record(project).read_text())["data_dirs"] == []


class TestFilesAreDataToo:
    def test_retired_file_mount_keeps_the_file(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        install_release(_release(tmp_path, "a", MOUNTS_STATE_FILE), project)
        (project / "state.json").write_text('{"counter": 7}')
        b = _release(tmp_path, "b", NO_MOUNTS)
        install_release(b, project)
        install_release(b, project)
        assert (project / "state.json").read_text() == '{"counter": 7}'

    def test_release_dropping_a_file_mount_cannot_overwrite_it(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        install_release(_release(tmp_path, "a", MOUNTS_STATE_FILE), project)
        (project / "state.json").write_text('{"counter": 7}')
        b = _release(tmp_path, "b", NO_MOUNTS, {"state.json": "{}"})
        with pytest.raises(BundleError, match="state.json"):
            install_release(b, project)
        assert (project / "state.json").read_text() == '{"counter": 7}'


class TestRecordStartsFromWhatTheBoxHolds:
    def test_kept_previous_release_seeds_the_record(self, tmp_path: Path) -> None:
        """A project already on B (A kept for rollback) before the record
        existed: A's mounts still say uploads/ is data."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "compose.yml").write_text(NO_MOUNTS)
        (project / "uploads").mkdir()
        (project / "uploads" / "photo.jpg").write_text("USER UPLOAD")
        previous = project / ".releases" / "previous"
        previous.mkdir(parents=True)
        (previous / "compose.yml").write_text(MOUNTS_UPLOADS)
        install_release(_release(tmp_path, "b", NO_MOUNTS), project)
        assert (project / "uploads" / "photo.jpg").exists()
        assert json.loads(_record(project).read_text()) == {
            "version": 1, "data_dirs": ["uploads"]}


class TestBadRecordFailsNoisily:
    @pytest.mark.parametrize("content,match", [
        ("{{{ not json", "Cannot read"),
        ('["uploads"]', "not a JSON object"),
        ('{"version": 2, "data_dirs": []}', "version 2"),
        ('{"data_dirs": []}', "version"),
        ('{"version": 1}', "data_dirs"),
        ('{"version": 1, "data_dirs": "uploads"}', "data_dirs"),
        ('{"version": 1, "data_dirs": ["../etc"]}', "data_dirs"),
    ])
    def test_refused_before_anything_changes(
        self, tmp_path: Path, project: Path, content: str, match: str,
    ) -> None:
        _record(project).write_text(content)
        (project / "old.txt").write_text("old code")
        b = _release(tmp_path, "b", NO_MOUNTS)
        with pytest.raises(ReleaseStateError, match=match):
            install_release(b, project)
        assert (project / "old.txt").exists()
        assert _record(project).read_text() == content

    def test_unreadable_record_is_refused(self, tmp_path: Path, project: Path) -> None:
        _record(project).unlink()
        _record(project).mkdir()  # a directory cannot be read as a file
        with pytest.raises(ReleaseStateError, match="Cannot read"):
            install_release(_release(tmp_path, "b", NO_MOUNTS), project)
        assert (project / "uploads" / "photo.jpg").exists()


# --- end to end: deploy and rollback -----------------------------------------

@contextmanager
def _docker():
    with patch("boxmunge.commands.deploy.compose_up"), \
            patch("boxmunge.commands.deploy.caddy_reload"):
        yield


def test_deploy_and_rollback_keep_retired_data(paths) -> None:
    from boxmunge.commands.deploy import run_deploy
    from boxmunge.commands.rollback import run_rollback
    from boxmunge.project_registry import add_project
    from tests.bundle_helpers import place_bundle

    add_project("myapp", paths)
    pdir = paths.project_dir("myapp")

    def deploy(ts: str, compose: str) -> None:
        place_bundle(paths, timestamp=ts, files={"compose.yml": compose})
        with _docker():
            assert run_deploy("myapp", paths) == 0

    deploy("2026-10-13T090000000000", MOUNTS_UPLOADS)
    (pdir / "uploads").mkdir()
    (pdir / "uploads" / "photo.jpg").write_text("USER UPLOAD")
    deploy("2026-10-13T100000000000", NO_MOUNTS)
    deploy("2026-10-13T110000000000", NO_MOUNTS)
    assert (pdir / "uploads" / "photo.jpg").read_text() == "USER UPLOAD"
    assert not (paths.project_releases("myapp") / "previous" / "uploads").exists()

    deploy("2026-10-13T120000000000", MOUNTS_UPLOADS)
    with _docker():
        assert run_rollback("myapp", paths, yes=True) == 0
    assert (pdir / "uploads" / "photo.jpg").read_text() == "USER UPLOAD"

    log = [json.loads(line) for line in paths.log_file.read_text().splitlines()]
    retained = [e for e in log if e["level"] == "warn" and "uploads/" in e["msg"]]
    assert retained and all(e["project"] == "myapp" for e in retained)


def test_stage_unstage_and_promote_keep_retired_data(paths, capsys) -> None:
    """A staged release that drops the mount shares the project dir with
    production, which still writes there."""
    from boxmunge.commands.deploy import run_deploy
    from boxmunge.commands.promote_cmd import run_promote
    from boxmunge.commands.stage_cmd import run_stage
    from boxmunge.commands.unstage_cmd import run_unstage
    from boxmunge.project_registry import add_project
    from tests.bundle_helpers import place_bundle
    from tests.test_commands.test_stage_promote_release import _docker as _stage_docker

    add_project("myapp", paths)
    pdir = paths.project_dir("myapp")
    place_bundle(paths, timestamp="2026-10-13T090000000000",
                 files={"compose.yml": MOUNTS_UPLOADS})
    with _stage_docker():
        assert run_deploy("myapp", paths) == 0
    (pdir / "uploads").mkdir()
    (pdir / "uploads" / "photo.jpg").write_text("USER UPLOAD")

    def without_mount(hour: int) -> str:
        ts = f"2026-10-13T{hour}0000000000"
        place_bundle(paths, timestamp=ts, files={"compose.yml": NO_MOUNTS})
        return ts

    with _stage_docker():
        assert run_stage("myapp", paths, ref=without_mount(10)) == 0
        assert run_stage("myapp", paths, ref=without_mount(11)) == 0
        assert run_unstage("myapp", paths) == 0
        assert (pdir / "uploads" / "photo.jpg").exists()
        assert run_stage("myapp", paths, ref=without_mount(12)) == 0
        assert run_promote("myapp", paths) == 0
        assert run_deploy("myapp", paths, ref=without_mount(13)) == 0
    assert (pdir / "uploads" / "photo.jpg").read_text() == "USER UPLOAD"
    assert "uploads/ holds data" in capsys.readouterr().out
    log = [json.loads(line) for line in paths.log_file.read_text().splitlines()]
    assert any(e["component"] == "stage" and e["level"] == "warn"
               and "uploads/" in e["msg"] for e in log)


# --- projects deployed before the record existed ------------------------------

def _deployer(paths):
    from boxmunge.commands.deploy import run_deploy
    from boxmunge.project_registry import add_project
    from tests.bundle_helpers import place_bundle
    add_project("myapp", paths)

    def deploy(hour: int, compose: str) -> int:
        place_bundle(paths, timestamp=f"2026-10-13T{hour:02d}0000000000",
                     files={"compose.yml": compose})
        with _docker():
            return run_deploy("myapp", paths)
    return deploy


def _pre_upgrade_box(paths) -> Path:
    """Live on B (no mount); A, kept for rollback, mounted ./uploads; no record."""
    deploy = _deployer(paths)
    pdir = paths.project_dir("myapp")
    assert deploy(9, MOUNTS_UPLOADS) == 0
    (pdir / "uploads").mkdir()
    (pdir / "uploads" / "photo.jpg").write_text("USER UPLOAD")
    assert deploy(10, NO_MOUNTS) == 0
    _record(pdir).unlink()
    return pdir


class TestPreUpgradeProjects:
    def test_first_deploy_after_upgrade_keeps_a_dir_retired_before_it(self, paths) -> None:
        from boxmunge.commands.deploy import run_deploy
        pdir = _pre_upgrade_box(paths)
        from tests.bundle_helpers import place_bundle
        for hour in (11, 12):
            place_bundle(paths, timestamp=f"2026-10-13T{hour}0000000000",
                         files={"compose.yml": NO_MOUNTS})
            with _docker():
                assert run_deploy("myapp", paths) == 0
            assert (pdir / "uploads" / "photo.jpg").read_text() == "USER UPLOAD"
        assert json.loads(_record(pdir).read_text())["data_dirs"] == ["uploads"]

    def test_crash_after_the_previous_release_swap_loses_nothing(self, paths) -> None:
        """previous/ already holds B when install_release fails: only the
        record still knows uploads/ is data."""
        from boxmunge.commands.deploy import run_deploy
        from tests.bundle_helpers import place_bundle
        pdir = _pre_upgrade_box(paths)
        place_bundle(paths, timestamp="2026-10-13T110000000000",
                     files={"compose.yml": NO_MOUNTS})
        with _docker(), patch("boxmunge.commands.deploy.install_release",
                              side_effect=OSError("disk full")):
            assert run_deploy("myapp", paths) == 1
        prev = paths.project_releases("myapp") / "previous" / "compose.yml"
        assert prev.read_text() == NO_MOUNTS
        place_bundle(paths, timestamp="2026-10-13T120000000000",
                     files={"compose.yml": NO_MOUNTS})
        with _docker():
            assert run_deploy("myapp", paths) == 0
        assert (pdir / "uploads" / "photo.jpg").read_text() == "USER UPLOAD"

    def test_promote_after_upgrade_keeps_a_dir_only_production_mounted(self, paths) -> None:
        from boxmunge.commands.deploy import run_deploy
        from boxmunge.commands.promote_cmd import run_promote
        from boxmunge.commands.stage_cmd import run_stage
        from tests.bundle_helpers import place_bundle
        from tests.test_commands.test_stage_promote_release import _docker as _stage_docker
        deploy = _deployer(paths)
        pdir = paths.project_dir("myapp")
        assert deploy(9, MOUNTS_UPLOADS) == 0
        (pdir / "uploads").mkdir()
        (pdir / "uploads" / "photo.jpg").write_text("USER UPLOAD")
        for hour in (10, 11):
            place_bundle(paths, timestamp=f"2026-10-13T{hour}0000000000",
                         files={"compose.yml": NO_MOUNTS})
        with _stage_docker():
            assert run_stage("myapp", paths, ref="2026-10-13T100000000000") == 0
            _record(pdir).unlink()
            assert run_promote("myapp", paths) == 0
            assert run_deploy("myapp", paths, ref="2026-10-13T110000000000") == 0
        assert (pdir / "uploads" / "photo.jpg").read_text() == "USER UPLOAD"


    def test_data_the_live_release_reads_read_only_survives_the_upgrade(
        self, paths,
    ) -> None:
        """B mounts ./uploads:ro and ships nothing for it: the data is still
        A's, and the read-only mount must not make it code."""
        from boxmunge.commands.deploy import run_deploy
        from tests.bundle_helpers import place_bundle
        reads_uploads = ("services:\n  web:\n    image: nginx\n"
                         "    volumes: [\"./uploads:/uploads:ro\"]\n")
        deploy = _deployer(paths)
        pdir = paths.project_dir("myapp")
        assert deploy(9, MOUNTS_UPLOADS) == 0
        (pdir / "uploads").mkdir()
        (pdir / "uploads" / "photo.jpg").write_text("USER UPLOAD")
        assert deploy(10, reads_uploads) == 0
        _record(pdir).unlink()
        for hour in (11, 12):
            place_bundle(paths, timestamp=f"2026-10-13T{hour}0000000000",
                         files={"compose.yml": reads_uploads})
            with _docker():
                assert run_deploy("myapp", paths) == 0
            assert (pdir / "uploads" / "photo.jpg").read_text() == "USER UPLOAD"


CONF_RW = ("services:\n  web:\n    image: nginx\n"
           "    volumes: [\"./conf:/etc/conf\"]\n")
CONF_RO = ("services:\n  web:\n    image: nginx\n"
           "    volumes: [\"./conf:/etc/conf:ro\"]\n")


def _live_with_old_rollback_target(tmp_path: Path, live_compose: str) -> Path:
    """Live release ships conf/ as code; the kept release mounted it rw."""
    project = tmp_path / "project"
    project.mkdir()
    (project / "compose.yml").write_text(live_compose)
    (project / "conf").mkdir()
    (project / "conf" / "app.conf").write_text("old conf")
    previous = project / ".releases" / "previous"
    previous.mkdir(parents=True)
    (previous / "compose.yml").write_text(CONF_RW)
    return project


class TestKeptReleasesOnlySeedTheRecord:
    def test_code_the_live_release_mounts_read_only_stays_code(self, tmp_path: Path) -> None:
        project = _live_with_old_rollback_target(tmp_path, CONF_RO)
        for n in range(2):
            tree = _release(tmp_path, f"c{n}", CONF_RO, {"conf/app.conf": f"conf {n}"})
            assert install_release(tree, project) == []
            assert (project / "conf" / "app.conf").read_text() == f"conf {n}"
        assert json.loads(_record(project).read_text())["data_dirs"] == []

    def test_refusal_names_the_kept_release_and_never_advises_deleting(
        self, tmp_path: Path,
    ) -> None:
        project = _live_with_old_rollback_target(tmp_path, NO_MOUNTS)
        tree = _release(tmp_path, "c", NO_MOUNTS, {"conf/app.conf": "new conf"})
        with pytest.raises(BundleError) as refused:
            install_release(tree, project)
        message = str(refused.value)
        assert "kept for rollback" in message and str(_record(project)) in message
        assert "rm -rf" not in message
        assert not _record(project).exists()
        _record(project).write_text('{"version": 1, "data_dirs": []}')
        install_release(tree, project)
        assert (project / "conf" / "app.conf").read_text() == "new conf"

    def test_without_an_incoming_release_a_kept_mount_counts(self, tmp_path: Path) -> None:
        """prestage_to_previous / discard_* know no incoming release: they
        must not drop data the live release only reads."""
        from boxmunge.data_dirs import classify
        project = _live_with_old_rollback_target(tmp_path, CONF_RO)
        kept = [project / ".releases" / "previous"]
        assert "conf" in classify(project, None, kept).recorded
        ships_conf = _release(tmp_path, "c", CONF_RO, {"conf/app.conf": "x"})
        assert "conf" not in classify(project, ships_conf, kept).recorded
        reads_conf = _release(tmp_path, "d", CONF_RO)
        assert "conf" in classify(project, reads_conf, kept).recorded

    def test_record_wins_over_kept_releases_once_it_exists(self, tmp_path: Path) -> None:
        project = _live_with_old_rollback_target(tmp_path, NO_MOUNTS)
        _record(project).write_text('{"version": 1, "data_dirs": []}')
        tree = _release(tmp_path, "c", NO_MOUNTS)
        install_release(tree, project)
        assert not (project / "conf").exists()


def test_staging_copy_alone_is_kept_without_a_warning_each_deploy(
    tmp_path: Path, project: Path, capsys,
) -> None:
    (project / "uploads-staging").mkdir()
    (project / "uploads-staging" / "photo.jpg").write_text("STAGING COPY")
    shutil.rmtree(project / "uploads")
    b = _release(tmp_path, "b", NO_MOUNTS)
    assert install_release(b, project) == []
    assert install_release(b, project) == []
    assert "WARNING" not in capsys.readouterr().out
    assert (project / "uploads-staging" / "photo.jpg").exists()
    assert json.loads(_record(project).read_text())["data_dirs"] == ["uploads"]
