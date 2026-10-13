"""Bundle content policy and installation into the live project tree.

On-box state belongs to the box, not to the bundle: ``secrets.env`` (CLI
managed), ``security/`` (suppressions and their history, audit B-15),
``data/`` and ``backups/``. A bundle carrying any of them is refused loudly.
An empty placeholder (``data/.gitkeep``) carries nothing and is dropped with
a note. Live data in user bind-mount dirs is never clobbered (v0.9.x
data-loss regression).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from boxmunge.bundle import BundleError, check_bundle_contents, copy_project_files


def _make_bundle(src: Path) -> None:
    """A representative bundle: manifest + compose + uploads bind dir."""
    src.mkdir(parents=True, exist_ok=True)
    (src / "manifest.yml").write_text("project: app\n")
    (src / "compose.yml").write_text(
        "services:\n"
        "  app:\n"
        "    volumes:\n"
        "      - ./data:/app/data\n"
        "      - ./uploads:/app/uploads\n"
    )
    (src / "uploads").mkdir()
    (src / "uploads" / ".gitkeep").write_text("")


def _live_project(dest: Path) -> None:
    dest.mkdir()
    (dest / "compose.yml").write_text(
        "services:\n"
        "  app:\n"
        "    volumes:\n"
        "      - ./data:/app/data\n"
        "      - ./uploads:/app/uploads\n"
    )
    (dest / "data").mkdir()
    (dest / "data" / "app.db").write_text("PRODUCTION DATA")
    (dest / "uploads").mkdir()
    (dest / "uploads" / "photo.jpg").write_text("USER UPLOAD")


class TestBoxOwnedEntriesRefused:
    @pytest.mark.parametrize("entry,content", [
        ("secrets.env", "DB_PASSWORD=from-a-laptop\n"),
        ("security/suppressions.yml", "suppressions: []\n"),
        ("data/seed.json", "{}"),
        ("backups/myapp-2026-01-01.tar.gz.age", "old snapshot"),
        ("repo/README", "stray clone"),
        (".releases/previous/compose.yml", "services: {}\n"),
        ("compose.boxmunge.yml", "services: {}\n"),
    ])
    def test_refused_with_named_entry(self, tmp_path: Path, entry: str,
                                      content: str) -> None:
        src = tmp_path / "bundle"
        _make_bundle(src)
        target = src / entry
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        with pytest.raises(BundleError) as exc:
            check_bundle_contents(src)
        assert entry.split("/")[0] in str(exc.value)

    @pytest.mark.parametrize("name", ["data", "backups", "security"])
    def test_empty_placeholder_dir_is_dropped_with_note(self, tmp_path: Path,
                                                        name: str) -> None:
        src = tmp_path / "bundle"
        _make_bundle(src)
        (src / name / "sub").mkdir(parents=True)
        (src / name / ".gitkeep").write_text("")
        (src / name / "sub" / ".keep").write_text("")
        notes = check_bundle_contents(src)
        assert not (src / name).exists()
        assert any(name in note for note in notes)

    def test_non_empty_gitkeep_is_content(self, tmp_path: Path) -> None:
        src = tmp_path / "bundle"
        _make_bundle(src)
        (src / "data").mkdir()
        (src / "data" / ".gitkeep").write_text("not empty")
        with pytest.raises(BundleError, match="data"):
            check_bundle_contents(src)

    def test_clean_bundle_passes_untouched(self, tmp_path: Path) -> None:
        src = tmp_path / "bundle"
        _make_bundle(src)
        (src / "project.env").write_text("LOG_LEVEL=info\n")
        assert check_bundle_contents(src) == []
        assert (src / "project.env").exists()

    def test_copy_refuses_box_owned_entry(self, tmp_path: Path) -> None:
        """copy_project_files never writes box-owned state, even if called
        without the content check."""
        src = tmp_path / "bundle"
        _make_bundle(src)
        (src / "secrets.env").write_text("X=1\n")
        dest = tmp_path / "project"
        _live_project(dest)
        (dest / "secrets.env").write_text("REAL=secret\n")
        with pytest.raises(BundleError):
            copy_project_files(src, dest, is_upgrade=True)
        assert (dest / "secrets.env").read_text() == "REAL=secret\n"


class TestInstall:
    def test_upgrade_preserves_live_bind_mount_dirs(self, tmp_path: Path) -> None:
        src = tmp_path / "bundle"
        dest = tmp_path / "project"
        _make_bundle(src)
        _live_project(dest)

        copy_project_files(src, dest, is_upgrade=True)

        assert (dest / "data" / "app.db").read_text() == "PRODUCTION DATA"
        assert (dest / "uploads" / "photo.jpg").read_text() == "USER UPLOAD"
        assert (dest / "manifest.yml").read_text() == "project: app\n"

    def test_skipping_live_bind_dir_is_reported(self, tmp_path: Path, capsys) -> None:
        src = tmp_path / "bundle"
        dest = tmp_path / "project"
        _make_bundle(src)
        (src / "uploads" / "default.png").write_text("SEED")
        _live_project(dest)

        copy_project_files(src, dest, is_upgrade=True)

        assert not (dest / "uploads" / "default.png").exists()
        assert "uploads" in capsys.readouterr().out

    def test_upgrade_seeds_empty_bind_mount_dir(self, tmp_path: Path) -> None:
        """A user bind-mount dir that exists but is empty has never held data:
        the bundle's seed content is copied in."""
        src = tmp_path / "bundle"
        dest = tmp_path / "project"
        _make_bundle(src)
        (src / "uploads" / "default.png").write_text("SEED")
        _live_project(dest)
        (dest / "uploads" / "photo.jpg").unlink()

        copy_project_files(src, dest, is_upgrade=True)

        assert (dest / "uploads" / "default.png").read_text() == "SEED"

    def test_project_env_comes_from_the_bundle(self, tmp_path: Path) -> None:
        """PROJECT_CONVENTIONS: project.env ships with the bundle and is
        replaced on each bundle deploy."""
        src = tmp_path / "bundle"
        dest = tmp_path / "project"
        _make_bundle(src)
        (src / "project.env").write_text("LOG_LEVEL=debug\n")
        _live_project(dest)
        (dest / "project.env").write_text("LOG_LEVEL=info\n")

        copy_project_files(src, dest, is_upgrade=True)

        assert (dest / "project.env").read_text() == "LOG_LEVEL=debug\n"

    def test_box_dirs_created_on_first_install(self, tmp_path: Path) -> None:
        src = tmp_path / "bundle"
        dest = tmp_path / "project"
        _make_bundle(src)
        dest.mkdir()

        copy_project_files(src, dest, is_upgrade=False)

        assert (dest / "data").is_dir()
        assert (dest / "backups").is_dir()
        assert (dest / "manifest.yml").exists()

    def test_upgrade_updates_code_dirs(self, tmp_path: Path) -> None:
        """Code dirs (e.g. boxmunge-scripts) ARE replaced."""
        src = tmp_path / "bundle"
        dest = tmp_path / "project"
        _make_bundle(src)
        (src / "boxmunge-scripts").mkdir()
        (src / "boxmunge-scripts" / "smoke.sh").write_text("new")

        dest.mkdir()
        (dest / "compose.yml").write_text("services: {}\n")
        (dest / "boxmunge-scripts").mkdir()
        (dest / "boxmunge-scripts" / "smoke.sh").write_text("old")
        (dest / "boxmunge-scripts" / "stale.sh").write_text("stale")

        copy_project_files(src, dest, is_upgrade=True)

        assert (dest / "boxmunge-scripts" / "smoke.sh").read_text() == "new"
        assert not (dest / "boxmunge-scripts" / "stale.sh").exists()

    def test_upgrade_preserves_bind_mount_dir_inode(self, tmp_path: Path) -> None:
        """A live prod container bind-mounts ./boxmunge-scripts by inode.

        Docker resolves a bind mount to the host directory's inode at container
        start. Replacing the directory with rmtree+copytree gives it a NEW
        inode, so the still-running prod container's mount keeps pointing at
        the deleted original: smoke.sh vanishes inside the container, the
        smoke check fails critical, and the health monitor stops prod. Install
        must refresh directory CONTENTS in place.
        """
        src = tmp_path / "bundle"
        dest = tmp_path / "project"
        _make_bundle(src)
        (src / "boxmunge-scripts").mkdir()
        (src / "boxmunge-scripts" / "smoke.sh").write_text("new")

        dest.mkdir()
        (dest / "compose.yml").write_text("services: {}\n")
        (dest / "boxmunge-scripts").mkdir()
        (dest / "boxmunge-scripts" / "smoke.sh").write_text("old")

        inode_before = (dest / "boxmunge-scripts").stat().st_ino
        copy_project_files(src, dest, is_upgrade=True)
        inode_after = (dest / "boxmunge-scripts").stat().st_ino

        assert inode_after == inode_before
        assert (dest / "boxmunge-scripts" / "smoke.sh").read_text() == "new"
