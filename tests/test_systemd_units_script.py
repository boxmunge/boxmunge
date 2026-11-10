# SPDX-License-Identifier: Apache-2.0
"""bootstrap/systemd-units.sh installs the systemd units and starts the
timers. `systemctl enable --now` leaves a running timer on the schedule it
loaded, so a timer whose unit file changed is restarted, and only that one."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "bootstrap" / "systemd-units.sh"
TIMERS = sorted(p.name for p in (REPO / "systemd").glob("*.timer"))


def _run(tmp_path: Path, bundle: Path) -> list[str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    log = tmp_path / "systemctl.log"
    stub = bin_dir / "systemctl"
    stub.write_text(f'#!/usr/bin/env bash\necho "$*" >> "{log}"\n')
    stub.chmod(0o755)
    log.write_text("")
    dest = tmp_path / "etc-systemd"
    dest.mkdir(exist_ok=True)
    subprocess.run(["bash", str(SCRIPT), str(bundle)], check=True, capture_output=True,
                   env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}",
                        "BOXMUNGE_SYSTEMD_DIR": str(dest)})
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
    assert calls[:2] == ["daemon-reload", "enable --now " + " ".join(TIMERS)]


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
    assert "enable --now" not in text
