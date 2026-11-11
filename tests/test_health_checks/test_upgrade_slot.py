# SPDX-License-Identifier: Apache-2.0
"""The upgrade-slot health check: deploy-writable active-slot must agree with
root's env-active. When they disagree (and no swap was interrupted) the shim
refuses every upgrade and every check-probation, so a planted active-slot
would otherwise stall the box with nothing reporting it."""
from __future__ import annotations

import pytest

from boxmunge.health_checks.upgrade_slot import check_upgrade_slot


@pytest.fixture
def box(paths):
    paths.upgrade_state.mkdir(parents=True)
    for slot in "ab":
        (paths.root / f"env-{slot}").mkdir()
    return paths


def _live(paths, link: str | None, file: str | None) -> None:
    if link is not None:
        (paths.root / "env-active").symlink_to(paths.root / f"env-{link}")
    if file is not None:
        paths.active_slot.write_text(file + "\n")


def test_ok_when_they_agree(box):
    _live(box, "a", "a")
    check = check_upgrade_slot(box)
    assert (check.name, check.status) == ("upgrade-slot", "ok")
    assert "slot a" in check.detail


def test_warns_when_active_slot_disagrees_with_env_active(box):
    _live(box, "a", "b")
    check = check_upgrade_slot(box)
    assert check.status == "warn"
    assert "says 'b' but env-active points at env-a" in check.detail
    assert f"echo a | sudo tee {box.active_slot}" in check.detail


def test_an_interrupted_swap_is_not_a_disagreement(box):
    """The shim follows env-active then, and rewrites active-slot itself."""
    _live(box, "a", "b")
    (box.root / "env-a" / "upgrade-inflight").write_text("1.5.0\n")
    assert check_upgrade_slot(box).status == "ok"


@pytest.mark.parametrize("content", ["c", "../env-a", ""])
def test_warns_on_an_active_slot_that_is_not_a_slot(box, content):
    _live(box, "a", content)
    check = check_upgrade_slot(box)
    assert check.status == "warn" and "not a or b" in check.detail


def test_warns_when_env_active_points_elsewhere(box, tmp_path):
    (box.root / "env-active").symlink_to(tmp_path)
    box.active_slot.write_text("a\n")
    check = check_upgrade_slot(box)
    assert check.status == "warn" and "not env-a or env-b" in check.detail


def test_a_planted_link_is_not_followed(box, tmp_path):
    _live(box, "a", None)
    (tmp_path / "elsewhere").write_text("a\n")
    box.active_slot.symlink_to(tmp_path / "elsewhere")
    check = check_upgrade_slot(box)
    assert check.status == "warn" and str(box.active_slot) in check.detail


def test_skips_off_a_box(paths):
    assert check_upgrade_slot(paths).status == "skip"


def test_is_part_of_health():
    import inspect

    from boxmunge.commands import health_cmd
    assert "check_upgrade_slot" in inspect.getsource(health_cmd._checks)
