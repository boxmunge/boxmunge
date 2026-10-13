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


def test_bundle_cannot_ship_a_caddy_override(paths, live, capsys) -> None:
    """caddy.override.conf is used verbatim as the project's Caddy config; a
    bundle must not be able to supply raw proxy config (P2 leftover)."""
    before = tree_snapshot(live)
    place_bundle(paths, timestamp="2026-10-13T100000000000",
                 files={"caddy.override.conf": "myapp.example.com { reverse_proxy evil:80 }\n"})
    with patch("boxmunge.commands.deploy.compose_up") as up:
        assert run_deploy("myapp", paths) == 1
    up.assert_not_called()
    assert tree_snapshot(live) == before
    err = capsys.readouterr().err
    assert "caddy.override.conf" in err and "operator" in err


def test_operator_placed_caddy_override_survives_deploys(paths, live) -> None:
    (live / "caddy.override.conf").write_text("myapp.example.com { respond 200 }\n")
    place_bundle(paths, timestamp="2026-10-13T100000000000", files={"VERSION": "v2\n"})
    with patch("boxmunge.commands.deploy.compose_up"), \
            patch("boxmunge.commands.deploy.caddy_reload"):
        assert run_deploy("myapp", paths) == 0
    assert (live / "caddy.override.conf").read_text() == "myapp.example.com { respond 200 }\n"
    assert not (live / ".releases" / "previous" / "caddy.override.conf").exists()


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


BIND_COMPOSE = ("services:\n  web:\n    image: nginx\n    volumes:\n"
                "      - ./static:/usr/share/nginx/html:ro\n"
                "      - ./uploads:/srv/uploads\n")


def test_read_only_bind_dir_is_updated_by_a_deploy(paths) -> None:
    """Review finding: bind-mounted code was silently never updated."""
    add_project("myapp", paths)
    pdir = paths.project_dir("myapp")
    with patch("boxmunge.commands.deploy.compose_up"), \
            patch("boxmunge.commands.deploy.caddy_reload"):
        place_bundle(paths, timestamp="2026-10-13T090000000000",
                     files={"compose.yml": BIND_COMPOSE, "static/index.html": "v1"})
        assert run_deploy("myapp", paths) == 0
        place_bundle(paths, timestamp="2026-10-13T100000000000",
                     files={"compose.yml": BIND_COMPOSE, "static/index.html": "v2"})
        assert run_deploy("myapp", paths) == 0
    assert (pdir / "static" / "index.html").read_text() == "v2"


def test_content_for_a_read_write_bind_dir_is_refused(paths, capsys) -> None:
    add_project("myapp", paths)
    pdir = paths.project_dir("myapp")
    with patch("boxmunge.commands.deploy.compose_up") as up, \
            patch("boxmunge.commands.deploy.caddy_reload"):
        place_bundle(paths, timestamp="2026-10-13T090000000000",
                     files={"compose.yml": BIND_COMPOSE})
        assert run_deploy("myapp", paths) == 0
        (pdir / "uploads").mkdir(exist_ok=True)
        (pdir / "uploads" / "photo.jpg").write_text("USER UPLOAD")
        before = tree_snapshot(pdir)
        up.reset_mock()
        place_bundle(paths, timestamp="2026-10-13T100000000000",
                     files={"compose.yml": BIND_COMPOSE, "uploads/seed.png": "x"})
        assert run_deploy("myapp", paths) == 1
    up.assert_not_called()
    assert tree_snapshot(pdir) == before
    err = capsys.readouterr().err
    assert "uploads/" in err and ":ro" in err
