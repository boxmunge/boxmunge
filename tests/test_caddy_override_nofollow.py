"""caddy.override.conf is read without following a link.

The project directory is deploy-writable, and `sudo prod-deploy|promote|
rollback|resume` read the override as root: a planted link to a root-only
file copied its content into a world-readable site file and the journal.
The override is now opened O_NOFOLLOW, must be a regular file, and is
capped at the size a site file may have.
"""
from __future__ import annotations

import os

import pytest

from boxmunge.caddy import site_config
from boxmunge.caddy_journal import MAX_SITE_BYTES
from boxmunge.paths import BoxPaths

_MANIFEST = {
    "project": "myapp", "hosts": ["myapp.example.com"],
    "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
}


@pytest.fixture
def override(paths: BoxPaths):
    paths.project_dir("myapp").mkdir(parents=True)
    return paths.project_caddy_override("myapp")


def test_a_regular_override_is_used(paths, override) -> None:
    override.write_text("myapp.example.com {\n    respond ok\n}\n")
    content, used = site_config(paths, "myapp", _MANIFEST)
    assert used == override and "respond ok" in content


def test_no_override_generates_the_site(paths, override) -> None:
    content, used = site_config(paths, "myapp", _MANIFEST)
    assert used is None and "myapp.example.com" in content


def test_a_linked_override_is_refused_without_reading_it(paths, override, tmp_path) -> None:
    secret = tmp_path / "root-only"
    secret.write_text("ROOT SECRET\n")
    override.symlink_to(secret)
    with pytest.raises(OSError, match="outside the project") as caught:
        site_config(paths, "myapp", _MANIFEST)
    assert "ROOT SECRET" not in str(caught.value)
    assert "remove it" in str(caught.value)


def test_a_fifo_override_is_refused_without_blocking(paths, override) -> None:
    os.mkfifo(override)
    with pytest.raises(OSError, match="not a regular file"):
        site_config(paths, "myapp", _MANIFEST)


def test_an_oversized_override_is_refused(paths, override) -> None:
    override.write_text("#" * (MAX_SITE_BYTES + 1))
    with pytest.raises(OSError, match="larger than"):
        site_config(paths, "myapp", _MANIFEST)


def test_a_link_that_stays_in_the_project_is_followed(paths, override) -> None:
    """A git project may keep its override in repo/ and link it, as
    boxmunge links compose.yml."""
    repo = override.parent / "repo"
    repo.mkdir()
    (repo / "caddy.override.conf").write_text("myapp.example.com {\n    respond repo\n}\n")
    override.symlink_to("repo/caddy.override.conf")
    content, used = site_config(paths, "myapp", _MANIFEST)
    assert used == override and "respond repo" in content


def test_a_link_through_a_linked_directory_out_of_the_project_is_refused(
        paths, override, tmp_path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "o.conf").write_text("SECRET\n")
    (override.parent / "repo").symlink_to(outside)
    override.symlink_to("repo/o.conf")
    with pytest.raises(OSError, match="outside the project"):
        site_config(paths, "myapp", _MANIFEST)
