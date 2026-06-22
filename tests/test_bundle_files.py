"""Regression tests for boxmunge.bundle.copy_project_files.

Critical data-loss bug (v0.9.x): a bundle legitimately ships a placeholder
``data/`` dir (e.g. holding ``.gitkeep``), and every project's live persistent
state lives in bind-mounted host dirs (``data/`` for the DB, ``backups/`` for
encrypted snapshots). The old copy loop ``rmtree``'d any bundle directory that
already existed in the project dir, so each redeploy silently destroyed the
live production ``data/`` and replaced it with the bundle's empty one.

These tests pin the invariant: on upgrade, persistent host dirs are NEVER
clobbered by the bundle.
"""
from __future__ import annotations

from pathlib import Path

from boxmunge.bundle import copy_project_files


def _make_bundle(src: Path) -> None:
    """A representative bundle: manifest + compose + seed data/.gitkeep."""
    src.mkdir(parents=True, exist_ok=True)
    (src / "manifest.yml").write_text("project: app\n")
    (src / "compose.yml").write_text(
        "services:\n"
        "  app:\n"
        "    volumes:\n"
        "      - ./data:/app/data\n"
        "      - ./uploads:/app/uploads\n"
    )
    (src / "data").mkdir()
    (src / "data" / ".gitkeep").write_text("")
    (src / "uploads").mkdir()
    (src / "uploads" / ".gitkeep").write_text("")


def test_upgrade_preserves_live_data_dir(tmp_path: Path) -> None:
    src = tmp_path / "bundle"
    dest = tmp_path / "project"
    _make_bundle(src)

    # Existing deployed project with live data and a compose declaring binds.
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

    copy_project_files(src, dest, is_upgrade=True)

    # The live DB and uploads MUST survive the redeploy untouched.
    assert (dest / "data" / "app.db").read_text() == "PRODUCTION DATA"
    assert (dest / "uploads" / "photo.jpg").read_text() == "USER UPLOAD"
    # New code (manifest/compose) is still updated.
    assert (dest / "manifest.yml").read_text() == "project: app\n"


def test_upgrade_preserves_backups_dir(tmp_path: Path) -> None:
    src = tmp_path / "bundle"
    dest = tmp_path / "project"
    _make_bundle(src)
    (src / "backups").mkdir()  # bundle ships an empty backups/ placeholder

    dest.mkdir()
    (dest / "backups").mkdir()
    snapshot = dest / "backups" / "app-2026-01-01.tar.gz.age"
    snapshot.write_text("ENCRYPTED SNAPSHOT")

    copy_project_files(src, dest, is_upgrade=True)

    assert snapshot.read_text() == "ENCRYPTED SNAPSHOT"


def test_upgrade_seeds_empty_persistent_dir(tmp_path: Path) -> None:
    """If the live persistent dir exists but is empty (volume never used),
    the bundle's seed content is copied in — a writable volume mounting over
    an empty host dir on first run otherwise leaves the app with no seed."""
    src = tmp_path / "bundle"
    dest = tmp_path / "project"
    _make_bundle(src)
    (src / "data" / "seed.json").write_text("INITIAL SEED")

    dest.mkdir()
    (dest / "compose.yml").write_text(
        "services:\n  app:\n    volumes:\n      - ./data:/app/data\n"
    )
    (dest / "data").mkdir()  # exists but EMPTY

    copy_project_files(src, dest, is_upgrade=True)

    assert (dest / "data" / "seed.json").read_text() == "INITIAL SEED"


def test_upgrade_does_not_seed_nonempty_persistent_dir(tmp_path: Path) -> None:
    """A persistent dir with ANY content is never reseeded — even a single
    file means the volume is in use and its data is authoritative."""
    src = tmp_path / "bundle"
    dest = tmp_path / "project"
    _make_bundle(src)
    (src / "data" / "seed.json").write_text("INITIAL SEED")

    dest.mkdir()
    (dest / "compose.yml").write_text(
        "services:\n  app:\n    volumes:\n      - ./data:/app/data\n"
    )
    (dest / "data").mkdir()
    (dest / "data" / "live.db").write_text("LIVE")  # any content => in use

    copy_project_files(src, dest, is_upgrade=True)

    assert (dest / "data" / "live.db").read_text() == "LIVE"
    assert not (dest / "data" / "seed.json").exists()


def test_fresh_deploy_still_copies_bundle_data(tmp_path: Path) -> None:
    """On a first deploy (not upgrade) the bundle's seed data is copied."""
    src = tmp_path / "bundle"
    dest = tmp_path / "project"
    _make_bundle(src)
    dest.mkdir()

    copy_project_files(src, dest, is_upgrade=False)

    assert (dest / "data" / ".gitkeep").exists()
    assert (dest / "manifest.yml").exists()


def test_upgrade_updates_non_persistent_dirs(tmp_path: Path) -> None:
    """Non-persistent bundle dirs (e.g. boxmunge-scripts) ARE replaced."""
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
    # rmtree semantics preserved for non-persistent dirs: stale file gone.
    assert not (dest / "boxmunge-scripts" / "stale.sh").exists()
