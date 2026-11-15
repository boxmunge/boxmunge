# SPDX-License-Identifier: Apache-2.0
"""Worker identity against a fake /proc tree."""
from pathlib import Path

import pytest

from boxmunge.api.worker_identity import WorkerIdentity, current, is_alive
from boxmunge.state import StateError

BOOT = "11111111-2222-3333-4444-555555555555"


def _stat(comm: str, start: int) -> str:
    # fields 3..21 (19 of them, state first), then field 22 = start time
    rest = ["S"] + ["0"] * 18 + [str(start)] + ["0"] * 5
    return f"123 {comm} " + " ".join(rest) + "\n"


def _proc(tmp_path: Path, pid: int, start: int, comm: str = "(python)",
          boot: str | None = BOOT) -> Path:
    if boot is not None:
        (tmp_path / "sys/kernel/random").mkdir(parents=True, exist_ok=True)
        (tmp_path / "sys/kernel/random/boot_id").write_text(boot + "\n")
    (tmp_path / str(pid)).mkdir(exist_ok=True)
    (tmp_path / str(pid) / "stat").write_text(_stat(comm, start))
    return tmp_path


def test_start_time_is_field_22_even_when_comm_has_spaces_and_parens(tmp_path):
    proc = _proc(tmp_path, 123, 987654, comm="(a) b)")
    ident = current(proc, pid=123)
    assert ident == WorkerIdentity(BOOT, 123, 987654)


def test_reboot_is_not_alive(tmp_path):
    proc = _proc(tmp_path, 7, 50)
    assert not is_alive(WorkerIdentity("other-boot", 7, 50), proc)


def test_pid_reuse_is_not_alive(tmp_path):
    proc = _proc(tmp_path, 7, 50)
    assert not is_alive(WorkerIdentity(BOOT, 7, 49), proc)


def test_missing_pid_is_not_alive(tmp_path):
    proc = _proc(tmp_path, 7, 50)
    assert not is_alive(WorkerIdentity(BOOT, 8, 50), proc)


def test_all_three_matching_is_alive(tmp_path):
    proc = _proc(tmp_path, 7, 50)
    assert is_alive(WorkerIdentity(BOOT, 7, 50), proc)


def test_unreadable_boot_id_raises_state_error(tmp_path):
    proc = _proc(tmp_path, 7, 50, boot=None)
    with pytest.raises(StateError, match="boot_id"):
        is_alive(WorkerIdentity(BOOT, 7, 50), proc)


def test_record_round_trip():
    ident = WorkerIdentity(BOOT, 7, 50)
    assert WorkerIdentity.from_record(ident.as_record()) == ident
    with pytest.raises(StateError, match="start_time"):
        WorkerIdentity.from_record({"boot_id": BOOT, "pid": 7})


@pytest.mark.parametrize("stat", ["garbage", "1 (a) S 0 0", "1 (a) " + " ".join(["x"] * 25)])
def test_unparseable_stat_raises_state_error(tmp_path, stat):
    proc = _proc(tmp_path, 7, 50)
    (proc / "7" / "stat").write_text(stat)
    with pytest.raises(StateError, match="stat"):
        is_alive(WorkerIdentity(BOOT, 7, 50), proc)
