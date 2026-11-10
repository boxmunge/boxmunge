# SPDX-License-Identifier: Apache-2.0
"""Every download on the root upgrade path has a time limit (U7).

The upgrade shim downloads the bundle, and install.sh (which an upgrade runs)
cosign and Trivy's key, all with upgrade.lock held: a stalled connection
without a limit parks the upgrade indefinitely, and check-probation skips
while the lock is held."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
UPGRADE_PATH = [
    REPO / "scripts" / "boxmunge-upgrade",
    *sorted((REPO / "scripts" / "boxmunge-upgrade.d").glob("*.sh")),
    REPO / "install.sh",
    REPO / "bootstrap" / "cosign.sh",
]
CURL = re.compile(r"^\s*(?:[^#\n]*[|;&({]\s*)?curl\s+([^\n]*(?:\\\n[^\n]*)*)", re.M)


def _curl_calls(path: Path) -> list[str]:
    return [m.group(1) for m in CURL.finditer(path.read_text())]


def test_the_upgrade_path_downloads() -> None:
    assert sum(len(_curl_calls(p)) for p in UPGRADE_PATH) >= 3


@pytest.mark.parametrize("path", UPGRADE_PATH, ids=lambda p: p.name)
def test_every_curl_has_a_connect_and_total_time_limit(path: Path) -> None:
    for call in _curl_calls(path):
        assert "--connect-timeout" in call and "--max-time" in call, f"{path.name}: curl {call}"
