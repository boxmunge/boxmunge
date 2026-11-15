"""project-delete removes the project's state kept outside its directory:
a project made again under the name must not inherit image pins, strict's
fix deadlines or a refused-start alert throttle."""
from __future__ import annotations

from unittest.mock import patch

from boxmunge.commands.project_delete_cmd import delete_locked
from boxmunge.start_alerts import record_path
from tests.stage_helpers import prod_and_stage


def test_delete_removes_pins_fix_deadlines_and_the_start_alert_throttle(
        paths, fake_containers) -> None:
    prod_and_stage(paths)
    left = [paths.project_image_pins("myapp"), paths.project_fix_grace("myapp"),
            record_path(paths, "myapp")]
    for path in left:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n")
    with patch("boxmunge.commands.project_delete_cmd.compose_down"), \
            patch("boxmunge.commands.project_delete_cmd.caddy_reload"):
        assert delete_locked("myapp", paths, force=False) == 0
    assert [p for p in left if p.exists()] == []


def test_delete_removes_autofix_records_and_marker(paths, fake_containers) -> None:
    prod_and_stage(paths)
    left = [paths.project_autofix_records("myapp"), paths.project_autofix_marker("myapp"),
            paths.project_autofix_queue("myapp"), paths.project_autofix_journal("myapp")]
    for path in left:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n")
    with patch("boxmunge.commands.project_delete_cmd.compose_down"), \
            patch("boxmunge.commands.project_delete_cmd.caddy_reload"):
        assert delete_locked("myapp", paths, force=False) == 0
    assert [p for p in left if p.exists()] == []
