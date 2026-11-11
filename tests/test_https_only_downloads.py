# SPDX-License-Identifier: Apache-2.0
"""Every download root runs follows redirects to https only.

Integrity is checked separately (cosign and sha256 for releases, pinned
hashes for cosign, gpg for the apt keys), so this closes a plaintext redirect
surface rather than a forgery one: `curl -L` follows a redirect to any scheme
unless told otherwise."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
ROOT_SCRIPTS = sorted([REPO / "install.sh", REPO / "system" / "Dockerfile",
                       *(REPO / "bootstrap").glob("*.sh"),
                       *(REPO / "scripts" / "boxmunge-upgrade.d").glob("*.sh")])
_CURL = re.compile(r"\bcurl\s+-")  # an invocation, not `command -v curl` or a package name


def _curls() -> list[tuple[str, str]]:
    return [(f"{path.relative_to(REPO)}:{n}", line) for path in ROOT_SCRIPTS
            for n, line in enumerate(path.read_text().splitlines(), 1)
            if _CURL.search(line) and not line.lstrip().startswith("#")]


def test_the_downloads_are_found() -> None:
    where = {w.split(":")[0] for w, _ in _curls()}
    assert {"install.sh", "system/Dockerfile", "bootstrap/cosign.sh",
            "scripts/boxmunge-upgrade.d/release.sh"} <= where


@pytest.mark.parametrize("where, line", _curls(), ids=[w for w, _ in _curls()])
def test_every_download_stays_on_https(where: str, line: str) -> None:
    assert "--proto =https" in line and "--proto-redir =https" in line, where
