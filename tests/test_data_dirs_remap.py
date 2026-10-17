"""D18: deploy does not move container-owned data aside on a remapped box."""
from __future__ import annotations

import os

import pytest

from boxmunge import data_dirs
from boxmunge.data_dirs import ContainerOwnedEntryError, DataDirs, holds_data, start_record
from tests.userns_helpers import remap_box


def _dirs(project_dir):
    return DataDirs(project_dir=project_dir, release=frozenset(), recorded=frozenset(),
                    mounted=frozenset({"uploads"}), adopted=frozenset({"uploads"}))


def _uploads(paths):
    project_dir = paths.project_dir("shop")
    (project_dir / "uploads").mkdir(parents=True)
    (project_dir / "uploads" / "a.jpg").write_text("x")
    return project_dir


def test_container_owned_entry_is_refused_when_remapped(paths, monkeypatch) -> None:
    project_dir = _uploads(paths)
    remap_box(paths, monkeypatch)
    monkeypatch.setattr(data_dirs, "_owned_by_me", lambda path: False)
    with pytest.raises(ContainerOwnedEntryError) as e:
        start_record(_dirs(project_dir))
    assert f"sudo mv {project_dir / 'uploads'}/*" in str(e.value)
    assert (project_dir / "uploads" / "a.jpg").exists()
    assert not data_dirs.has_record(project_dir)


def test_deploy_owned_entry_still_moves_when_remapped(paths, monkeypatch) -> None:
    project_dir = _uploads(paths)
    remap_box(paths, monkeypatch)
    copies = start_record(_dirs(project_dir))
    assert len(copies) == 1 and (copies[0] / "a.jpg").exists()


def test_unremapped_box_moves_as_before(paths, monkeypatch) -> None:
    project_dir = _uploads(paths)
    monkeypatch.setattr(data_dirs, "_owned_by_me", lambda path: False)
    assert len(start_record(_dirs(project_dir))) == 1


@pytest.mark.skipif(os.geteuid() == 0, reason="root lists any directory")
def test_unlistable_directory_is_presumed_to_hold_data_and_not_owned(tmp_path) -> None:
    d = tmp_path / "pg"
    d.mkdir()
    d.chmod(0)
    try:
        assert holds_data(d) is True
        assert data_dirs._owned_by_me(d) is False
    finally:
        d.chmod(0o755)


def test_check_install_refuses_before_anything_changes(paths, monkeypatch, tmp_path) -> None:
    from boxmunge.release import check_install
    project_dir = _uploads(paths)
    (project_dir / "compose.yml").write_text(
        "services:\n  app:\n    image: x\n    volumes:\n      - ./uploads:/u\n")
    remap_box(paths, monkeypatch)
    monkeypatch.setattr(data_dirs, "_owned_by_me", lambda path: False)
    monkeypatch.setattr("boxmunge.release._classify", lambda project_dir, tree: _dirs(project_dir))
    tree = tmp_path / "tree"
    (tree / "uploads").mkdir(parents=True)
    (tree / "uploads" / "index.html").write_text("code")
    with pytest.raises(ContainerOwnedEntryError):
        check_install(tree, project_dir)
