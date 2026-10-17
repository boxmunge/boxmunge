"""project-delete takes staging down from the slot."""
from __future__ import annotations

from unittest.mock import patch

from boxmunge.commands.project_delete_cmd import delete_locked
from boxmunge.staged_release import STAGING_BASE, STAGING_OVERLAY, slot_dir
from tests.stage_helpers import prod_and_stage


def test_delete_takes_staging_down_from_the_slot(paths, fake_containers) -> None:
    prod_and_stage(paths)
    slot = slot_dir(paths, "myapp")
    with patch("boxmunge.commands.project_delete_cmd.compose_down") as down, \
            patch("boxmunge.commands.project_delete_cmd.caddy_reload"):
        assert delete_locked("myapp", paths, force=False) == 0
    staging = [c for c in down.call_args_list if c.kwargs["project_name"] == "myapp-staging"]
    assert len(staging) == 1
    assert staging[0].kwargs["project_directory"] == slot / "release"
    assert staging[0].kwargs["compose_files"] == [str(slot / STAGING_BASE),
                                                  str(slot / STAGING_OVERLAY)]
    assert staging[0].kwargs["remove_orphans"] is True
    assert not paths.project_dir("myapp").exists()


def test_a_planted_slot_link_deletes_nothing(paths, fake_containers, tmp_path, capsys) -> None:
    """A link in place of the slot is not followed for compose files; the
    teardown fails, so nothing is deleted (as for any teardown failure)."""
    prod_and_stage(paths)
    slot = slot_dir(paths, "myapp")
    moved = tmp_path / "elsewhere"
    slot.rename(moved)
    slot.symlink_to(moved)
    with patch("boxmunge.commands.project_delete_cmd.compose_down") as down, \
            patch("boxmunge.commands.project_delete_cmd.caddy_reload"):
        assert delete_locked("myapp", paths, force=False) == 1
    assert all(c.kwargs["project_name"] != "myapp-staging" for c in down.call_args_list)
    assert paths.project_dir("myapp").is_dir()
    assert "symbolic link" in capsys.readouterr().err
