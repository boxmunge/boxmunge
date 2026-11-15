"""A successful release switch forgets the patch records and the autofixing
marker along with the image pins (deploy_steps.clear_release_overrides)."""
from __future__ import annotations

from boxmunge.commands.deploy_steps import clear_release_overrides


def test_switch_forgets_patch_records_and_marker(paths) -> None:
    files = [paths.project_autofix_records("shop"), paths.project_autofix_marker("shop")]
    for f in files:
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("{}\n")
    other = paths.project_autofix_records("blog")
    other.write_text("{}\n")
    clear_release_overrides(paths, "shop")
    assert [f for f in files if f.exists()] == []
    assert other.exists()
