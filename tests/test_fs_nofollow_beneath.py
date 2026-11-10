"""Walks that follow no link at any depth (fs_nofollow.open_dir_beneath,
open_resolved_nofollow). O_NOFOLLOW on a path checks its last component
only; these walk one component at a time from a directory descriptor."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from boxmunge.fs_nofollow import open_dir_beneath, open_resolved_nofollow


def test_a_real_path_opens(tmp_path: Path) -> None:
    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / "a" / "b" / "f").write_text("x")
    fd = open_resolved_nofollow(Path(os.path.realpath(tmp_path / "a" / "b" / "f")), os.O_RDONLY)
    with os.fdopen(fd) as f:
        assert f.read() == "x"


def test_a_link_in_the_middle_is_refused(tmp_path: Path) -> None:
    real = Path(os.path.realpath(tmp_path))
    (real / "elsewhere").mkdir()
    (real / "elsewhere" / "f").write_text("secret")
    (real / "a").symlink_to("elsewhere")
    with pytest.raises(OSError):
        open_resolved_nofollow(real / "a" / "f", os.O_RDONLY)
    with pytest.raises(OSError):
        open_dir_beneath(real, ["a"])


def test_a_final_link_is_refused(tmp_path: Path) -> None:
    real = Path(os.path.realpath(tmp_path))
    (real / "f").write_text("x")
    (real / "l").symlink_to("f")
    with pytest.raises(OSError, match="symlink"):
        open_resolved_nofollow(real / "l", os.O_RDONLY)


@pytest.mark.parametrize("parts", [[".."], ["a", ".."], [""]])
def test_parts_must_be_plain_names(tmp_path: Path, parts: list[str]) -> None:
    (tmp_path / "a").mkdir()
    with pytest.raises(OSError):
        open_dir_beneath(tmp_path, parts)
