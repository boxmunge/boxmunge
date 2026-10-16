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

from boxmunge import staging_data, staging_placeholders
from boxmunge.staging_placeholders import make_placeholder


def _no_containers(monkeypatch) -> list:
    calls: list = []
    monkeypatch.setattr(staging_data, "run_throwaway",
                        lambda project, mounts, script: calls.append((mounts, script)))
    return calls


def test_nested_placeholders_are_made_on_the_host(tmp_path: Path, monkeypatch) -> None:
    calls = _no_containers(monkeypatch)
    make_placeholder("myapp", tmp_path, "store-staging/deep/app.db", is_file=True)
    make_placeholder("myapp", tmp_path, "app.db-staging", is_file=True)
    make_placeholder("myapp", tmp_path, "data-staging/db", is_file=False)
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
        make_placeholder("myapp", tmp_path / "project", "store-staging/app.db", is_file=True)
    assert list(elsewhere.iterdir()) == []


@pytest.mark.skipif(os.getuid() == 0, reason="root can write anywhere")
def test_a_directory_owned_by_another_user_uses_a_container_and_hands_it_back(
        tmp_path: Path, monkeypatch) -> None:
    calls = _no_containers(monkeypatch)
    holder = tmp_path / "store-staging"
    holder.mkdir()
    holder.chmod(0o555)  # as a copy of data owned by a container user would be
    try:
        make_placeholder("myapp", tmp_path, "store-staging/sub/app.db", is_file=True)
    finally:
        holder.chmod(0o755)
    (mounts, script), = calls
    assert mounts == ["-v", f"{holder}:/x"]
    uid, gid = staging_placeholders._owner()
    assert script == (f"mkdir -p /x/sub && touch /x/sub/app.db && "
                      f"chown -h {uid}:{gid} /x/sub /x/sub/app.db")
