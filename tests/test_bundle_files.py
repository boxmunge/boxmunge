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

from boxmunge.bundle import BundleError, check_bundle_contents
from boxmunge.release import install_release


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
            install_release(src, dest)
        assert (dest / "secrets.env").read_text() == "REAL=secret\n"


class TestInstall:
    def test_upgrade_preserves_live_bind_mount_dirs(self, tmp_path: Path) -> None:
        src = tmp_path / "bundle"
        dest = tmp_path / "project"
        _make_bundle(src)
        _live_project(dest)

        install_release(src, dest)

        assert (dest / "data" / "app.db").read_text() == "PRODUCTION DATA"
        assert (dest / "uploads" / "photo.jpg").read_text() == "USER UPLOAD"
        assert (dest / "manifest.yml").read_text() == "project: app\n"

    def test_placeholder_for_live_data_dir_is_kept_with_note(
        self, tmp_path: Path, capsys,
    ) -> None:
        src = tmp_path / "bundle"
        dest = tmp_path / "project"
        _make_bundle(src)  # ships uploads/.gitkeep only
        _live_project(dest)
        install_release(src, dest)
        assert (dest / "uploads" / "photo.jpg").read_text() == "USER UPLOAD"
        assert not (dest / "uploads" / ".gitkeep").exists()
        assert "uploads" in capsys.readouterr().out

    def test_project_env_comes_from_the_bundle(self, tmp_path: Path) -> None:
        """PROJECT_CONVENTIONS: project.env ships with the bundle and is
        replaced on each bundle deploy."""
        src = tmp_path / "bundle"
        dest = tmp_path / "project"
        _make_bundle(src)
        (src / "project.env").write_text("LOG_LEVEL=debug\n")
        _live_project(dest)
        (dest / "project.env").write_text("LOG_LEVEL=info\n")

        install_release(src, dest)

        assert (dest / "project.env").read_text() == "LOG_LEVEL=debug\n"

    def test_box_dirs_created_on_first_install(self, tmp_path: Path) -> None:
        src = tmp_path / "bundle"
        dest = tmp_path / "project"
        _make_bundle(src)
        dest.mkdir()

        install_release(src, dest)

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

        install_release(src, dest)

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
        install_release(src, dest)
        inode_after = (dest / "boxmunge-scripts").stat().st_ino

        assert inode_after == inode_before
        assert (dest / "boxmunge-scripts" / "smoke.sh").read_text() == "new"


class TestLinksAreNeverFollowed:
    def test_internal_link_is_installed_as_a_link(self, tmp_path: Path) -> None:
        src = tmp_path / "bundle"
        dest = tmp_path / "project"
        _make_bundle(src)
        (src / "loop").symlink_to(".")
        dest.mkdir()
        install_release(src, dest)
        assert (dest / "loop").is_symlink()

    def test_live_link_is_replaced_not_written_through(self, tmp_path: Path) -> None:
        """An old release's `scripts -> data` link must not turn the new
        release's scripts/ install into a wipe of live data/."""
        src = tmp_path / "bundle"
        dest = tmp_path / "project"
        _make_bundle(src)
        (src / "scripts").mkdir()
        (src / "scripts" / "run.sh").write_text("new")
        (src / "config.txt").write_text("new config")
        _live_project(dest)
        (dest / "scripts").symlink_to("data")
        (dest / "config.txt").symlink_to("data/app.db")

        install_release(src, dest)

        assert (dest / "data" / "app.db").read_text() == "PRODUCTION DATA"
        assert not (dest / "scripts").is_symlink()
        assert (dest / "scripts" / "run.sh").read_text() == "new"
        assert not (dest / "config.txt").is_symlink()
        assert (dest / "config.txt").read_text() == "new config"


def _release(src: Path, compose: str) -> None:
    src.mkdir(parents=True)
    (src / "manifest.yml").write_text("project: app\n")
    (src / "compose.yml").write_text(compose)


class TestEveryBindMountFormProtectsData:
    """Review finding: only short-syntax `./x` sources were recognised; long
    syntax and absolute sources were treated as release code and deleted by
    the next install that did not ship them."""

    LONG = ("services:\n  app:\n    volumes:\n"
            "      - type: bind\n        source: ./uploads\n        target: /u\n")

    def _live(self, dest: Path, compose: str) -> None:
        dest.mkdir()
        (dest / "compose.yml").write_text(compose)
        (dest / "uploads").mkdir()
        (dest / "uploads" / "photo.jpg").write_text("USER UPLOAD")

    def test_long_syntax_bind_survives_install(self, tmp_path: Path) -> None:
        from boxmunge.release import live_code_entries
        dest = tmp_path / "project"
        self._live(dest, self.LONG)
        src = tmp_path / "bundle"
        _release(src, self.LONG)
        assert dest / "uploads" not in live_code_entries(dest, src)
        install_release(src, dest)
        assert (dest / "uploads" / "photo.jpg").read_text() == "USER UPLOAD"

    def test_absolute_source_under_the_project_survives_install(self, tmp_path: Path) -> None:
        dest = tmp_path / "project"
        compose = f"services:\n  app:\n    volumes:\n      - {dest}/uploads:/u\n"
        self._live(dest, compose)
        src = tmp_path / "bundle"
        _release(src, compose)
        install_release(src, dest)
        assert (dest / "uploads" / "photo.jpg").read_text() == "USER UPLOAD"

    @pytest.mark.parametrize("compose", [
        "services: [not, a, mapping]\n",
        "services:\n  app:\n    volumes: ./uploads:/u\n",
        "services: {app: [1]}\n",
        "{{{ not yaml\n",
    ])
    def test_unreadable_live_compose_refuses_before_any_change(
        self, tmp_path: Path, compose: str,
    ) -> None:
        from boxmunge.release import ReleaseStateError
        dest = tmp_path / "project"
        self._live(dest, compose)
        (dest / "old.txt").write_text("old")
        src = tmp_path / "bundle"
        _release(src, "services: {}\n")
        with pytest.raises(ReleaseStateError, match="compose.yml"):
            install_release(src, dest)
        assert (dest / "old.txt").exists()
        assert (dest / "uploads" / "photo.jpg").exists()


RO = ("services:\n  app:\n    volumes:\n"
      "      - ./static:/usr/share/nginx/html:ro\n"
      "      - type: bind\n        source: ./config\n        target: /etc/app\n"
      "        read_only: true\n"
      "      - ./uploads:/u\n")


class TestOnlyReadWriteBindsAreData:
    """Review finding: a non-empty bind-mounted code/config dir was silently
    never updated, and deploy exited 0 running old code."""

    def _live(self, dest: Path) -> None:
        dest.mkdir()
        (dest / "compose.yml").write_text(RO)
        for d in ("static", "config", "uploads"):
            (dest / d).mkdir()
        (dest / "static" / "index.html").write_text("old page")
        (dest / "config" / "app.conf").write_text("old conf")
        (dest / "uploads" / "photo.jpg").write_text("USER UPLOAD")

    def test_read_only_bind_dirs_are_release_code(self, tmp_path: Path) -> None:
        from boxmunge.release import live_code_entries
        dest = tmp_path / "project"
        self._live(dest)
        src = tmp_path / "bundle"
        _release(src, RO)
        (src / "static").mkdir()
        (src / "static" / "index.html").write_text("new page")
        (src / "config").mkdir()
        (src / "config" / "app.conf").write_text("new conf")

        assert {e.name for e in live_code_entries(dest, src)} >= {"static", "config"}
        install_release(src, dest)

        assert (dest / "static" / "index.html").read_text() == "new page"
        assert (dest / "config" / "app.conf").read_text() == "new conf"
        assert (dest / "uploads" / "photo.jpg").read_text() == "USER UPLOAD"

    def test_content_for_a_read_write_bind_dir_is_refused_untouched(
        self, tmp_path: Path,
    ) -> None:
        dest = tmp_path / "project"
        self._live(dest)
        src = tmp_path / "bundle"
        _release(src, RO)
        (src / "uploads").mkdir()
        (src / "uploads" / "default.png").write_text("SEED")
        (dest / "stale.txt").write_text("stale")
        with pytest.raises(BundleError, match="uploads.*read-write"):
            install_release(src, dest)
        assert (dest / "stale.txt").exists()
        assert not (dest / "uploads" / "default.png").exists()

    def test_first_install_refuses_content_for_its_own_read_write_bind(
        self, tmp_path: Path,
    ) -> None:
        """Consistent from the first deploy: otherwise the seeded dir would
        make every later deploy of the same bundle fail."""
        dest = tmp_path / "project"
        dest.mkdir()
        src = tmp_path / "bundle"
        _release(src, RO)
        (src / "uploads").mkdir()
        (src / "uploads" / "default.png").write_text("SEED")
        with pytest.raises(BundleError, match="uploads"):
            install_release(src, dest)
