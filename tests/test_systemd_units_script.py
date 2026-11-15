# SPDX-License-Identifier: Apache-2.0
"""bootstrap/systemd-units.sh installs the systemd units and starts the
timers. `systemctl enable --now` leaves a running timer on the schedule it
loaded, so a timer whose unit file changed is restarted, and only that one."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "bootstrap" / "systemd-units.sh"
TIMERS = sorted(p.name for p in (REPO / "systemd").glob("*.timer"))
PATHS = sorted(p.name for p in (REPO / "systemd").glob("*.path"))
ENABLED = sorted(TIMERS + PATHS)


def _run(tmp_path: Path, bundle: Path, **env: str) -> list[str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    log = tmp_path / "systemctl.log"
    stub = bin_dir / "systemctl"
    stub.write_text(f'#!/usr/bin/env bash\necho "$*" >> "{log}"\n')
    stub.chmod(0o755)
    log.write_text("")
    dest = tmp_path / "etc-systemd"
    dest.mkdir(exist_ok=True)
    if env.get("FROM_UPGRADE_SHIM") == "1" and "BOXMUNGE_ROOT" not in env:
        # As the shim runs it: env-a live, this release in env-b.
        for slot in ("env-a", "env-b"):
            (tmp_path / slot).mkdir(exist_ok=True)
        if not (tmp_path / "env-active").is_symlink():
            (tmp_path / "env-active").symlink_to(tmp_path / "env-a")
        env["BOXMUNGE_ROOT"] = str(tmp_path)
    subprocess.run(["bash", str(SCRIPT), str(bundle)], check=True, capture_output=True,
                   env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}",
                        "BOXMUNGE_SYSTEMD_DIR": str(dest), **env})
    return log.read_text().splitlines()


def _bundle(tmp_path: Path) -> Path:
    bundle = tmp_path / "bundle"
    (bundle / "systemd").mkdir(parents=True)
    for unit in (REPO / "systemd").iterdir():
        (bundle / "systemd" / unit.name).write_bytes(unit.read_bytes())
    return bundle


def test_installs_every_unit_and_enables_every_timer(tmp_path) -> None:
    calls = _run(tmp_path, _bundle(tmp_path))
    installed = sorted(p.name for p in (tmp_path / "etc-systemd").iterdir())
    assert installed == sorted(p.name for p in (REPO / "systemd").iterdir())
    assert calls[:2] == ["daemon-reload", "enable --now " + " ".join(ENABLED)]


def test_installs_the_path_unit_and_enables_it(tmp_path) -> None:
    """The path unit is the job runner's start, at boot and on every queued
    job; its service has no [Install] and is never enabled itself."""
    calls = _run(tmp_path, _bundle(tmp_path))
    dest = tmp_path / "etc-systemd"
    assert PATHS == ["boxmunge-jobs.path"]
    assert (dest / "boxmunge-jobs.path").is_file() and (dest / "boxmunge-jobs.service").is_file()
    enabled = calls[1].split()
    assert "boxmunge-jobs.path" in enabled and "boxmunge-jobs.service" not in enabled


def test_a_changed_path_unit_is_restarted_so_its_watch_applies(tmp_path) -> None:
    bundle = _bundle(tmp_path)
    _run(tmp_path, bundle)
    changed = bundle / "systemd" / "boxmunge-jobs.path"
    changed.write_text(changed.read_text() + "# changed\n")
    assert _run(tmp_path, bundle)[-1] == "restart boxmunge-jobs.path"


def test_units_record_includes_path_units(tmp_path) -> None:
    """A rollback to the slot installs its path units again, and removes any
    its record lacks, so the record holds them, as the live set and as the
    bundle's."""
    dest = tmp_path / "etc-systemd"
    dest.mkdir()
    for name in ("boxmunge-health.timer", "boxmunge-jobs.path", "boxmunge-jobs.service"):
        (dest / name).write_text(f"old {name}\n")
    record = tmp_path / "env-a" / "boxmunge-systemd"
    bundle = _bundle(tmp_path)
    _run(tmp_path, bundle, BOXMUNGE_SLOT_UNITS=str(record), FROM_UPGRADE_SHIM="1")
    assert sorted(p.name for p in record.iterdir()) == [
        "boxmunge-health.timer", "boxmunge-jobs.path", "boxmunge-jobs.service"]
    _run(tmp_path, bundle, BOXMUNGE_SLOT_UNITS=str(record), FROM_UPGRADE_SHIM="0")
    assert (record / "boxmunge-jobs.path").read_text() == (
        REPO / "systemd" / "boxmunge-jobs.path").read_text()


def test_an_unchanged_timer_is_not_restarted(tmp_path) -> None:
    bundle = _bundle(tmp_path)
    _run(tmp_path, bundle)
    assert not [c for c in _run(tmp_path, bundle) if c.startswith("restart")]


def test_a_changed_timer_is_restarted_so_its_schedule_applies(tmp_path) -> None:
    bundle = _bundle(tmp_path)
    _run(tmp_path, bundle)
    changed = bundle / "systemd" / "boxmunge-backup.timer"
    changed.write_text(changed.read_text().replace("OnCalendar=", "OnCalendar=*-*-* 05:00\n#"))
    calls = _run(tmp_path, bundle)
    assert calls[-1] == "restart boxmunge-backup.timer"


def test_install_sh_installs_the_units_through_it() -> None:
    text = (REPO / "install.sh").read_text()
    assert 'bash "${SCRIPT_DIR}/bootstrap/systemd-units.sh" "${SCRIPT_DIR}"' in text
    assert 'BOXMUNGE_SLOT_UNITS="${BOXMUNGE_ROOT}/env-active/boxmunge-systemd"' in text
    assert "enable --now" not in text


def test_old_timers_removed_on_upgrade(tmp_path) -> None:
    bundle = _bundle(tmp_path)
    dest = tmp_path / "etc-systemd"
    dest.mkdir()
    old = ("boxmunge-cve-scan.timer", "boxmunge-container-update.timer")
    for name in old:
        (dest / name).write_text("[Timer]\n")
    calls = _run(tmp_path, bundle)
    for name in old:
        assert f"disable --now {name}" in calls
        assert not (dest / name).exists()
    assert calls.index("disable --now " + old[0]) < calls.index("daemon-reload")


def test_cleanup_is_a_noop_when_the_old_timers_are_gone(tmp_path) -> None:
    calls = _run(tmp_path, _bundle(tmp_path))
    assert not [c for c in calls if c.startswith("disable")]


def test_an_upgrade_records_the_units_the_live_slot_ran_before_replacing_them(tmp_path) -> None:
    """The previous release's units, the timers this release retires among
    them, are what a rollback to the live slot installs again."""
    dest = tmp_path / "etc-systemd"
    dest.mkdir()
    for name in ("boxmunge-cve-scan.timer", "boxmunge-health.timer", "boxmunge-health.service",
                 "other.service"):
        (dest / name).write_text(f"old {name}\n")
    record = tmp_path / "env-a" / "boxmunge-systemd"
    bundle = _bundle(tmp_path)
    _run(tmp_path, bundle, BOXMUNGE_SLOT_UNITS=str(record), FROM_UPGRADE_SHIM="1")
    assert sorted(p.name for p in record.iterdir()) == [
        "boxmunge-cve-scan.timer", "boxmunge-health.service", "boxmunge-health.timer"]
    assert (record / "boxmunge-health.timer").read_text() == "old boxmunge-health.timer\n"
    _run(tmp_path, bundle, BOXMUNGE_SLOT_UNITS=str(record), FROM_UPGRADE_SHIM="1")
    assert (record / "boxmunge-cve-scan.timer").exists()   # a record is kept as it is


def test_an_install_by_hand_records_the_bundles_units(tmp_path) -> None:
    dest = tmp_path / "etc-systemd"
    dest.mkdir()
    (dest / "boxmunge-stale.timer").write_text("stale\n")
    record = tmp_path / "env-a" / "boxmunge-systemd"
    bundle = _bundle(tmp_path)
    _run(tmp_path, bundle, BOXMUNGE_SLOT_UNITS=str(record), FROM_UPGRADE_SHIM="1")
    assert (record / "boxmunge-stale.timer").exists()
    _run(tmp_path, bundle, BOXMUNGE_SLOT_UNITS=str(record), FROM_UPGRADE_SHIM="0")
    assert sorted(p.name for p in record.iterdir()) == sorted(
        p.name for p in (REPO / "systemd").iterdir())
    # Swapped in by rename: one versioned directory left, the record links to it.
    assert record.is_symlink()
    assert [p.name for p in record.parent.iterdir() if p.name != "boxmunge-systemd"] == [
        str(record.readlink())]


def test_a_record_cut_short_leaves_the_previous_one(tmp_path) -> None:
    """The copy fails part-way (cp dies): the record still names the old set."""
    dest = tmp_path / "etc-systemd"
    dest.mkdir()
    (dest / "boxmunge-health.timer").write_text("old\n")
    record = tmp_path / "env-a" / "boxmunge-systemd"
    bundle = _bundle(tmp_path)
    _run(tmp_path, bundle, BOXMUNGE_SLOT_UNITS=str(record), FROM_UPGRADE_SHIM="1")
    bin_dir = tmp_path / "bin"
    (bin_dir / "cp").write_text("#!/usr/bin/env bash\nexit 1\n")
    (bin_dir / "cp").chmod(0o755)
    with pytest.raises(subprocess.CalledProcessError):
        _run(tmp_path, bundle, BOXMUNGE_SLOT_UNITS=str(record), FROM_UPGRADE_SHIM="0")
    assert [p.name for p in record.iterdir()] == ["boxmunge-health.timer"]
    assert (record / "boxmunge-health.timer").read_text() == "old\n"


def test_under_the_shim_the_standby_slot_records_this_bundles_units(tmp_path) -> None:
    """The record an older shim wrote for the standby lacks the path unit
    (0.11.11's copies only .service and .timer units): it is written again
    from this bundle, so the 0.12 heal does not remove the job runner's
    trigger. The live slot's record is still the units it ran."""
    dest = tmp_path / "etc-systemd"
    dest.mkdir()
    (dest / "boxmunge-health.timer").write_text("old boxmunge-health.timer\n")
    stale = tmp_path / "env-b" / "boxmunge-systemd"
    (tmp_path / "env-b" / ".boxmunge-systemd.OLD").mkdir(parents=True)  # the shim's scheme
    stale.symlink_to(".boxmunge-systemd.OLD")
    (stale / "boxmunge-health.timer").write_text("partial\n")
    live = tmp_path / "env-a" / "boxmunge-systemd"
    _run(tmp_path, _bundle(tmp_path), BOXMUNGE_SLOT_UNITS=str(tmp_path / "env-active" /
                                                             "boxmunge-systemd"),
         FROM_UPGRADE_SHIM="1")
    assert sorted(p.name for p in stale.iterdir()) == sorted(
        p.name for p in (REPO / "systemd").iterdir())
    assert "boxmunge-jobs.path" in [p.name for p in stale.iterdir()]
    assert [p.name for p in live.iterdir()] == ["boxmunge-health.timer"]
    assert (live / "boxmunge-health.timer").read_text() == "old boxmunge-health.timer\n"
    assert not (tmp_path / "env-b" / ".boxmunge-systemd.OLD").exists()  # replaced whole


@pytest.mark.parametrize("active", ["env-c", None])
def test_under_the_shim_an_unknown_live_slot_fails_loudly(tmp_path, active) -> None:
    (tmp_path / "env-a").mkdir()
    if active:
        (tmp_path / "env-active").symlink_to(tmp_path / active)
    with pytest.raises(subprocess.CalledProcessError) as raised:
        _run(tmp_path, _bundle(tmp_path), BOXMUNGE_ROOT=str(tmp_path),
             BOXMUNGE_SLOT_UNITS=str(tmp_path / "env-a" / "boxmunge-systemd"),
             FROM_UPGRADE_SHIM="1")
    assert b"not env-a or env-b" in raised.value.stderr
