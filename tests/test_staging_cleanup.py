# SPDX-License-Identifier: Apache-2.0
"""Unstage removes staging's copies of data production no longer mounts.

A copy holding data is emptied by a container (its files belong to the
container's users); that path runs against real Docker in
tests/integration/test_staging_copy.py.
"""
from __future__ import annotations

import json

from boxmunge.staging_cleanup import remove_retired_staging_data, retired_staging_copies


def _project(paths, compose: str, record: list[str]):
    pdir = paths.project_dir("myapp")
    (pdir / ".releases").mkdir(parents=True)
    (pdir / ".releases" / "data-dirs.json").write_text(
        json.dumps({"version": 1, "data_dirs": record}))
    (pdir / "compose.yml").write_text(compose)
    return pdir


def test_only_copies_of_unmounted_data_are_retired(paths) -> None:
    pdir = _project(paths, "services:\n  web:\n    image: x\n    volumes:\n"
                           "      - ./uploads:/u\n", ["uploads", "media"])
    for name in ("uploads-staging", "media-staging", "appconfig-staging"):
        (pdir / name).mkdir()
        (pdir / name / "f").write_text("staging's")
    assert retired_staging_copies(pdir) == [pdir / "media-staging"]


def test_removal_is_logged_and_leaves_production_data(paths) -> None:
    pdir = _project(paths, "services:\n  web:\n    image: x\n", ["media"])
    (pdir / "media").mkdir()
    (pdir / "media" / "photo").write_text("production's")
    (pdir / "media-staging").mkdir()
    assert remove_retired_staging_data(paths, "myapp") == [pdir / "media-staging"]
    assert not (pdir / "media-staging").exists()
    assert (pdir / "media" / "photo").read_text() == "production's"
    log = (paths.root / "logs" / "boxmunge.log").read_text()
    assert "Removed staging data media-staging" in log


def test_an_entry_production_mounts_is_never_a_staging_copy(paths) -> None:
    """Review of PR #65: production's own ./cache-staging is its data."""
    pdir = _project(paths, "services:\n  web:\n    image: x\n    volumes:\n"
                           "      - ./cache-staging:/c\n", ["cache", "cache-staging"])
    for name in ("cache", "cache-staging"):
        (pdir / name).mkdir()
        (pdir / name / "f").write_text("production's")
    assert retired_staging_copies(pdir) == []
    pdir_compose = pdir / "compose.yml"
    pdir_compose.write_text("services:\n  web:\n    image: x\n")
    # No longer mounted, but recorded as data in its own right: still kept.
    assert retired_staging_copies(pdir) == []


def test_old_layout_copies_are_reported_not_removed(paths, capsys) -> None:
    pdir = _project(paths, "services:\n  db:\n    image: x\n    volumes:\n"
                           "      - ./data/db:/var/lib/db\n", ["data"])
    (pdir / "data" / "db").mkdir(parents=True)
    (pdir / "data" / "db-staging").mkdir()
    (pdir / "data" / "db-staging" / "f").write_text("old staging copy")
    assert remove_retired_staging_data(paths, "myapp") == []
    assert (pdir / "data" / "db-staging" / "f").exists()
    assert f"rm -rf {pdir / 'data' / 'db-staging'}" in capsys.readouterr().out


def test_old_copies_of_release_code_are_reported(paths, capsys) -> None:
    pdir = _project(paths, "services:\n  web:\n    image: x\n    volumes:\n"
                           "      - ./appconfig:/etc/app:ro\n", [])
    (pdir / "appconfig").mkdir()
    (pdir / "appconfig-staging").mkdir()
    (pdir / "appconfig-staging" / "settings").write_text("old staging copy")
    assert remove_retired_staging_data(paths, "myapp") == []
    assert (pdir / "appconfig-staging" / "settings").exists()
    assert f"rm -rf {pdir / 'appconfig-staging'}" in capsys.readouterr().out


def test_a_copy_holding_data_is_emptied_by_the_helper(paths, monkeypatch) -> None:
    from boxmunge import staging_cleanup
    pdir = _project(paths, "services:\n  web:\n    image: x\n", ["media"])
    (pdir / "media-staging").mkdir()
    (pdir / "media-staging" / "photo").write_text("a container's")
    emptied = []

    def empty(label, path):
        emptied.append((label, path))
        (path / "photo").unlink()
    monkeypatch.setattr(staging_cleanup, "empty_dir", empty)
    assert remove_retired_staging_data(paths, "myapp") == [pdir / "media-staging"]
    assert emptied == [("myapp-staging-cleanup", pdir / "media-staging")]
