# SPDX-License-Identifier: Apache-2.0
"""Review of #159 (P3-5): read_target_state raises its own error, naming the
file, for any unreadable record (a link or FIFO refused by the no-follow
read, text that is not UTF-8, corrupt JSON); container-update's per-target
handling then marks that target failed with the reason."""
from __future__ import annotations

import os

import pytest

from boxmunge.container_update_targets import TargetStateError, read_target_state


@pytest.mark.parametrize("make", ["link", "fifo", "not-utf8", "corrupt"])
def test_an_unreadable_record_is_a_target_state_error(paths, tmp_path, make) -> None:
    path = paths.container_update_target_state("t")
    path.parent.mkdir(parents=True)
    if make == "link":
        (tmp_path / "x.json").write_text("{}")
        path.symlink_to(tmp_path / "x.json")
    elif make == "fifo":
        os.mkfifo(path)
    else:
        path.write_bytes(b"\xff\xfe" if make == "not-utf8" else b"{nope")
    with pytest.raises(TargetStateError, match=str(path)):
        read_target_state(paths, "t")


def test_a_missing_record_is_none(paths) -> None:
    assert read_target_state(paths, "t") is None
