"""The shift's id rules, mount detection, link checks and no-follow reach
(no root needed: run as an ordinary user on Linux)."""
from __future__ import annotations

import os
import stat

import pytest

from boxmunge.userns import shift
from boxmunge.userns.shift import Direction, mount_points_under, scan_tree
from boxmunge.userns.walk import closed_to_other, open_parent_nofollow

S = 1048576


@pytest.mark.parametrize("value, direction, expected", [
    (0, Direction.FORWARD, S), (65535, Direction.FORWARD, S + 65535),
    (S + 70, Direction.FORWARD, S + 70), (70000, Direction.FORWARD, None),
    (S + 70, Direction.INVERSE, 70), (70, Direction.INVERSE, 70),
    (2 * S, Direction.INVERSE, None),
])
def test_id_rules(value, direction, expected) -> None:
    assert shift._new_id(value, S, direction) == expected


def test_ids_in_range_pass_a_forward_shift_only_once_one_began() -> None:
    assert shift._new_id(S + 70, S, Direction.FORWARD, resumed=False) is None
    assert shift._new_id(70, S, Direction.FORWARD, resumed=False) == S + 70


@pytest.mark.parametrize("bad", [0, -S, S + 1])
def test_offset_must_be_a_positive_multiple_of_the_range(tmp_path, bad) -> None:
    with pytest.raises(ValueError):
        scan_tree(tmp_path, bad, Direction.FORWARD)


def test_mountinfo_escapes_are_decoded(tmp_path) -> None:
    info = tmp_path / "mountinfo"
    info.write_text(f"36 25 0:32 / {tmp_path}/m\\040p rw - tmpfs tmpfs rw\n"
                    f"37 25 0:33 / /elsewhere rw - tmpfs tmpfs rw\n"
                    f"38 25 0:34 / {tmp_path}x rw - tmpfs tmpfs rw\n")
    assert mount_points_under(tmp_path, info) == [f"{tmp_path}/m p"]


def test_a_hard_link_to_an_inode_outside_the_tree_is_refused(tmp_path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tmp_path / "outside").write_text("x")
    os.link(tmp_path / "outside", tree / "inside")
    problems = scan_tree(tree, S, Direction.INVERSE).problems
    assert any("hard link to a file outside the tree" in p for p in problems)


def test_hard_links_inside_the_tree_are_fine(tmp_path) -> None:
    (tmp_path / "a").write_text("x")
    os.link(tmp_path / "a", tmp_path / "b")
    assert scan_tree(tmp_path, S, Direction.INVERSE).problems == []


def test_a_symlink_root_is_refused(tmp_path) -> None:
    os.symlink("/", tmp_path / "link")
    assert scan_tree(tmp_path / "link", S, Direction.FORWARD).problems == [
        f"{tmp_path / 'link'}: is a symlink"]


def test_a_link_on_the_way_to_the_root_is_refused(tmp_path) -> None:
    """A container or deploy could swap a directory above the data for a
    link to /; the walk is never redirected through it."""
    (tmp_path / "real" / "data").mkdir(parents=True)
    os.symlink(tmp_path / "real", tmp_path / "project")
    problems = scan_tree(tmp_path / "project" / "data", S, Direction.FORWARD).problems
    assert len(problems) == 1 and "cannot be reached without following a link" in problems[0]
    with pytest.raises(OSError):
        open_parent_nofollow(tmp_path / "project" / "data")


def test_the_scan_lists_entries_a_chown_would_strip(tmp_path) -> None:
    for name, mode in (("suid", 0o4755), ("sgid-x", 0o2750), ("sgid-nox", 0o2640),
                       ("plain", 0o755)):
        (tmp_path / name).write_text("x")
        os.chmod(tmp_path / name, mode)
    (tmp_path / "dir").mkdir()
    os.chmod(tmp_path / "dir", 0o2775)
    assert scan_tree(tmp_path, S, Direction.INVERSE).setid == {"suid": 0o4755, "sgid-x": 0o2750}


def test_too_many_setid_files_are_refused(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(shift, "MAX_SETID", 1)
    for name in ("a", "b"):
        (tmp_path / name).write_text("x")
        os.chmod(tmp_path / name, 0o4755)
    assert any("2 setuid or setgid files" in p
               for p in scan_tree(tmp_path, S, Direction.INVERSE).problems)


def test_entries_closed_to_other_are_listed(tmp_path) -> None:
    (tmp_path / "open.txt").write_text("x")
    (tmp_path / "closed.txt").write_text("x")
    os.chmod(tmp_path / "closed.txt", 0o640)
    (tmp_path / "sub").mkdir()
    os.chmod(tmp_path / "sub", 0o750)
    os.chmod(tmp_path, 0o755)
    os.symlink("/nowhere", tmp_path / "link")
    assert sorted(closed_to_other(tmp_path)) == [f"{tmp_path}/closed.txt", f"{tmp_path}/sub"]
    assert closed_to_other(tmp_path / "open.txt") == []


def test_the_walk_counts_every_entry_once(tmp_path) -> None:
    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / "a" / "b" / "f").write_text("x")
    os.mkfifo(tmp_path / "fifo")
    os.symlink("a", tmp_path / "l")
    scan = scan_tree(tmp_path, S, Direction.INVERSE)
    assert scan.problems == [] and scan.entries == 6
    assert stat.S_ISFIFO(os.lstat(tmp_path / "fifo").st_mode)
