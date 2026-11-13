# SPDX-License-Identifier: Apache-2.0
"""How deploy's new sudo rule (`check *`, `guide *`) reaches a box.

An upgrade writes the sudo rule from the old shim, before it self-updates, so
the new shim's rule arrives only through install.sh, which an upgrade re-runs
only when the installer fingerprint changes. 0.11.8's fingerprint must
therefore differ from 0.11.7's: bootstrap/prerequisites (the readiness check's
box checks) is new under bootstrap/, which the fingerprint covers. The
fixture is the fingerprint of the v0.11.7 tag's tree, computed once from
`git archive v0.11.7` with the expression below.
"""
from __future__ import annotations

import re
from pathlib import Path

from tests.test_installer_fingerprint import _expr, _fingerprint

REPO = Path(__file__).resolve().parents[1]
FIXTURE = REPO / "tests" / "fixtures" / "installer-fingerprint-v0.11.7.txt"
MANIFEST = REPO / "bootstrap" / "prerequisites"
ENTRY = re.compile(r"bootstrap/[a-z0-9-]+\.sh")
# install.sh's first step that changes the system; its prerequisite checks
# must all run before it.
FIRST_CHANGE = "# Dead CrowdSec apt source."


def _prerequisites() -> list[str]:
    lines = [line.strip() for line in MANIFEST.read_text().splitlines()]
    return [line for line in lines if line and not line.startswith("#")]


def test_installer_fingerprint_differs_from_v0_11_7(tmp_path: Path) -> None:
    old = FIXTURE.read_text().strip()
    assert re.fullmatch(r"[0-9a-f]{64}", old), old
    # The shim's own expression (system.sh), the one an upgrade compares.
    assert _expr(REPO / "scripts" / "boxmunge-upgrade.d" / "system.sh") == _expr(
        REPO / "bootstrap" / "installer-fingerprint.sh")
    assert _fingerprint(REPO, tmp_path) != old


def test_prerequisites_manifest_is_covered_by_the_fingerprint(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    (bundle / "bootstrap").mkdir(parents=True)
    (bundle / "install.sh").write_text("install\n")
    manifest = bundle / "bootstrap" / "prerequisites"
    manifest.write_text(MANIFEST.read_text())
    before = _fingerprint(bundle, tmp_path)
    manifest.write_text(MANIFEST.read_text() + "bootstrap/new-check.sh\n")
    assert _fingerprint(bundle, tmp_path) != before


def test_every_prerequisite_is_run_by_install_sh_before_it_changes_anything() -> None:
    entries = _prerequisites()
    assert entries == ["bootstrap/upgrade-floor.sh", "bootstrap/python-floor.sh", "bootstrap/compose-version.sh"]
    install = (REPO / "install.sh").read_text()
    assert install.count(FIRST_CHANGE) == 1, "install.sh layout changed; move this test's cut point"
    head = install.split(FIRST_CHANGE)[0]
    for entry in entries:
        assert ENTRY.fullmatch(entry), entry
        assert (REPO / entry).is_file(), entry
        assert f'bash "${{SCRIPT_DIR}}/{entry}"' in head, f"install.sh does not run {entry} before it changes anything"
