# SPDX-License-Identifier: Apache-2.0
"""Copy placeholders belong to the user who runs boxmunge.

Containers write as root on Linux, so a placeholder a container made could
not be replaced or removed by the deploy user later (CI caught this on
Linux; Docker Desktop hides ownership). The real-Docker run is in
tests/integration/test_staging_copy.py.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from boxmunge import staging_placeholders
from boxmunge.staging_placeholders import make_placeholder


def _no_containers(monkeypatch) -> list:
    calls: list = []
    monkeypatch.setattr(staging_placeholders, "run_helper",
                        lambda label, mounts, script: calls.append((label, mounts, script)))
    return calls


def test_nested_placeholders_are_made_on_the_host(tmp_path: Path, monkeypatch) -> None:
    calls = _no_containers(monkeypatch)
    make_placeholder("myapp", tmp_path, "store-staging/deep/app.db", is_file=True, remapped=False)
    make_placeholder("myapp", tmp_path, "app.db-staging", is_file=True, remapped=False)
    make_placeholder("myapp", tmp_path, "data-staging/db", is_file=False, remapped=False)
    assert calls == []
    assert (tmp_path / "store-staging/deep/app.db").is_file()
    assert (tmp_path / "app.db-staging").is_file()
    assert (tmp_path / "data-staging/db").is_dir()
    assert (tmp_path / "store-staging").stat().st_uid == os.getuid()


def test_a_link_on_the_way_is_never_followed(tmp_path: Path, monkeypatch) -> None:
    _no_containers(monkeypatch)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (tmp_path / "project").mkdir()
    (tmp_path / "project" / "store-staging").symlink_to(elsewhere)
    with pytest.raises(OSError):
        make_placeholder("myapp", tmp_path / "project", "store-staging/app.db", is_file=True, remapped=False)
    assert list(elsewhere.iterdir()) == []


@pytest.mark.skipif(os.getuid() == 0, reason="root can write anywhere")
def test_a_directory_owned_by_another_user_uses_a_container_and_hands_it_back(
        tmp_path: Path, monkeypatch) -> None:
    calls = _no_containers(monkeypatch)
    holder = tmp_path / "store-staging"
    holder.mkdir()
    holder.chmod(0o555)  # as a copy of data owned by a container user would be
    try:
        make_placeholder("myapp", tmp_path, "store-staging/sub/app.db", is_file=True, remapped=False)
    finally:
        holder.chmod(0o755)
    (label, mounts, script), = calls
    assert label == "myapp-staging-copy"
    assert mounts == ["-v", f"{holder}:/x"]
    uid, gid = staging_placeholders._owner()
    assert script == (f"mkdir -p /x/sub && touch /x/sub/app.db && "
                      f"chown -h {uid}:{gid} /x/sub /x/sub/app.db")


def test_remapped_box_makes_placeholders_through_the_daemon(tmp_path: Path, monkeypatch) -> None:
    """Containers cannot write a deploy-owned placeholder on a remapped box:
    the daemon creates the directory (container root's) and the helper the
    rest, with no chown back to deploy."""
    calls = _no_containers(monkeypatch)
    make_placeholder("myapp", tmp_path, "uploads-staging", is_file=False, remapped=True)
    make_placeholder("myapp", tmp_path, "store-staging/deep/app.db", is_file=True,
                     remapped=True)
    assert not (tmp_path / "uploads-staging").exists()  # the daemon makes it
    assert calls[0] == ("myapp-staging-copy", ["-v", f"{tmp_path / 'uploads-staging'}:/x"],
                        "true")
    _, mounts, script = calls[1]
    assert mounts == ["-v", f"{tmp_path / 'store-staging'}:/x"]
    assert script == "mkdir -p /x/deep && touch /x/deep/app.db"


def test_remapped_box_never_mounts_through_a_link(tmp_path: Path, monkeypatch) -> None:
    calls = _no_containers(monkeypatch)
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "store-staging").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(OSError, match="symlink"):
        make_placeholder("myapp", tmp_path, "store-staging/app.db", is_file=True,
                         remapped=True)
    assert calls == []

