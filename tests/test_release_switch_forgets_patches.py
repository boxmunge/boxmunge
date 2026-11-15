"""A successful release switch forgets the patch records, the autofixing
marker and a queued urgent patch along with the image pins
(deploy_steps.clear_release_overrides)."""
from __future__ import annotations

from boxmunge.commands.deploy_steps import clear_release_overrides


def test_switch_forgets_patch_records_marker_and_queued_patch(paths) -> None:
    files = [paths.project_autofix_records("shop"), paths.project_autofix_marker("shop"),
             paths.project_autofix_queue("shop")]
    for f in files:
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("{}\n")
    others = [paths.project_autofix_records("blog"), paths.project_autofix_queue("blog")]
    for f in others:
        f.write_text("{}\n")
    clear_release_overrides(paths, "shop")
    assert [f for f in files if f.exists()] == []
    assert all(f.exists() for f in others)


def test_a_queue_entry_link_is_unlinked_not_followed(paths, tmp_path) -> None:
    target = tmp_path / "elsewhere.json"
    target.write_text("{}\n")
    entry = paths.project_autofix_queue("shop")
    entry.parent.mkdir(parents=True, exist_ok=True)
    entry.symlink_to(target)
    clear_release_overrides(paths, "shop")
    assert not entry.is_symlink() and target.exists()
