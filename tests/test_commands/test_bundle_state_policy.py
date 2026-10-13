"""A bundle can never overwrite on-box state (audit B-15, E cross-area).

secrets.env, security/ (suppressions and history), data/ and backups/ are
owned by the box. A deploy or stage of a bundle that carries them is refused
before anything changes, with an error that names the entry.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.stage_cmd import run_stage
from boxmunge.project_registry import add_project

from tests.bundle_helpers import place_bundle, tree_snapshot


@pytest.fixture
def live(paths):
    """A deployed project holding secrets, suppressions with history, data."""
    add_project("myapp", paths)
    place_bundle(paths, timestamp="2026-10-13T090000000000")
    with patch("boxmunge.commands.deploy.compose_up"), \
            patch("boxmunge.commands.deploy.caddy_reload"):
        assert run_deploy("myapp", paths) == 0
    pdir = paths.project_dir("myapp")
    (pdir / "secrets.env").write_text("DB_PASSWORD=real\n")
    (pdir / "security").mkdir()
    (pdir / "security" / "suppressions.yml").write_text("suppressions: [reviewed]\n")
    (pdir / "security" / "suppressions.history.yml").write_text("history: [audit]\n")
    (pdir / "data" / "app.db").write_text("PRODUCTION")
    return pdir


@pytest.mark.parametrize("entry,content,hint", [
    ("secrets.env", "DB_PASSWORD=laptop\n", "secrets set"),
    ("security/suppressions.yml", "suppressions: []\n", "security suppress"),
    ("data/app.db", "DEV DATA", "data"),
    ("backups/old.tar.gz.age", "x", "backups"),
])
def test_deploy_refuses_bundle_carrying_box_state(
    paths, live, capsys, entry, content, hint,
) -> None:
    before = tree_snapshot(live)
    bundle = place_bundle(paths, timestamp="2026-10-13T100000000000",
                          files={entry: content})
    with patch("boxmunge.commands.deploy.compose_up") as up:
        rc = run_deploy("myapp", paths)
    assert rc == 1
    up.assert_not_called()
    assert tree_snapshot(live) == before
    err = capsys.readouterr().err
    assert entry.split("/")[0] in err
    assert hint in err
    assert bundle.exists()


def test_stage_refuses_bundle_carrying_suppressions(paths, live, capsys) -> None:
    before = tree_snapshot(live)
    place_bundle(paths, timestamp="2026-10-13T100000000000",
                 files={"security/suppressions.yml": "suppressions: []\n"})
    with patch("boxmunge.commands.stage_cmd.compose_up") as up:
        rc = run_stage("myapp", paths)
    assert rc == 1
    up.assert_not_called()
    assert tree_snapshot(live) == before
    assert (live / "security" / "suppressions.history.yml").read_text() == "history: [audit]\n"


def test_placeholder_data_dir_is_accepted(paths, live, capsys) -> None:
    place_bundle(paths, timestamp="2026-10-13T100000000000",
                 files={"data/.gitkeep": "", "VERSION": "v2\n"})
    with patch("boxmunge.commands.deploy.compose_up"), \
            patch("boxmunge.commands.deploy.caddy_reload"):
        assert run_deploy("myapp", paths) == 0
    assert (live / "data" / "app.db").read_text() == "PRODUCTION"
    assert (live / "VERSION").read_text() == "v2\n"
    assert "placeholder" in capsys.readouterr().out


@pytest.mark.parametrize("form", ["long", "absolute"])
def test_bind_mounted_data_survives_a_deploy_that_does_not_ship_it(paths, form) -> None:
    """Review finding: long-syntax and absolute bind sources were treated as
    release code and deleted by the next deploy."""
    pdir = paths.project_dir("myapp")
    if form == "long":
        volume = ("      - type: bind\n        source: ./uploads\n"
                  "        target: /srv/uploads\n")
    else:
        volume = f"      - {pdir}/uploads:/srv/uploads\n"
    compose = "services:\n  web:\n    image: nginx\n    volumes:\n" + volume
    add_project("myapp", paths)
    place_bundle(paths, timestamp="2026-10-13T090000000000",
                 files={"compose.yml": compose, "uploads/.gitkeep": ""})
    with patch("boxmunge.commands.deploy.compose_up"), \
            patch("boxmunge.commands.deploy.caddy_reload"):
        assert run_deploy("myapp", paths) == 0
        (pdir / "uploads" / "photo.jpg").write_text("USER UPLOAD")
        place_bundle(paths, timestamp="2026-10-13T100000000000",
                     files={"compose.yml": compose})
        assert run_deploy("myapp", paths) == 0
    assert (pdir / "uploads" / "photo.jpg").read_text() == "USER UPLOAD"
    assert not (pdir / ".releases" / "previous" / "uploads").exists()
