"""The staging Caddy site goes through caddy_journal like production's.

A staging site Caddy rejects must be rolled back by the reload, not left on
disk to break the next reload of every project. unstage removes the site
and forgets its journal entry, so a later restore never brings back the
routing of a torn-down staging.
"""
from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import patch

from boxmunge.caddy_journal import JOURNAL_DIRNAME, remove_site, restore_sites, write_site
from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.stage_cmd import run_stage
from boxmunge.commands.unstage_cmd import run_unstage
from boxmunge.project_registry import add_project

from tests.bundle_helpers import place_bundle

V1 = "2026-10-13T090000000000"
V2 = "2026-10-13T100000000000"


@contextmanager
def _containers():
    with patch("boxmunge.commands.deploy.compose_up"), \
            patch("boxmunge.commands.stage_cmd.compose_up"), \
            patch("boxmunge.commands.unstage_cmd.compose_down"):
        yield


def _prod(paths) -> None:
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1)
    with _containers(), patch("boxmunge.commands.deploy.caddy_reload"):
        assert run_deploy("myapp", paths) == 0
    place_bundle(paths, timestamp=V2)


def test_rejected_staging_site_is_rolled_back_by_the_reload(paths, capsys) -> None:
    _prod(paths)
    with _containers(), \
            patch("boxmunge.docker.caddy_validate", return_value=False), \
            patch("boxmunge.docker.container_running", return_value=True):
        run_stage("myapp", paths)
    assert not paths.project_staging_caddy_site("myapp").exists()
    assert "myapp-staging.conf" in capsys.readouterr().out


def test_unstage_removes_the_site_and_forgets_its_journal_entry(paths) -> None:
    _prod(paths)
    with _containers(), patch("boxmunge.commands.stage_cmd.caddy_reload"), \
            patch("boxmunge.commands.unstage_cmd.caddy_reload"):
        assert run_stage("myapp", paths) == 0
        site = paths.project_staging_caddy_site("myapp")
        assert site.exists()
        assert _journaled(paths, site)
        assert run_unstage("myapp", paths) == 0
    assert not site.exists()
    assert not _journaled(paths, site)
    assert "myapp-staging.conf" not in restore_sites(paths.caddy)
    assert not site.exists()


def _journaled(paths, site) -> bool:
    return (paths.caddy / JOURNAL_DIRNAME / f"{site.name}.json").exists()


def test_remove_site_drops_file_and_entry(tmp_path) -> None:
    caddy = tmp_path / "caddy"
    site = caddy / "sites" / "myapp-staging.conf"
    site.parent.mkdir(parents=True)
    write_site(caddy, site, "staging.myapp.example.com {}\n")
    remove_site(caddy, site)
    assert not site.exists()
    assert restore_sites(caddy) == []
    remove_site(caddy, site)  # idempotent
