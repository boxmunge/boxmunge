# SPDX-License-Identifier: Apache-2.0
"""Fixtures for the action API tests."""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Iterator

import pytest

from boxmunge.api.dev.fixture import make_fixture
from boxmunge.paths import BoxPaths


@pytest.fixture
def fixture_paths(tmp_path: Path) -> BoxPaths:
    """A freshly written dev fixture box, timestamps relative to now."""
    return make_fixture(tmp_path / "box")


@pytest.fixture
def sock_path() -> Iterator[Path]:
    """A socket path short enough for AF_UNIX (104 bytes on macOS)."""
    directory = Path(tempfile.mkdtemp(prefix="bm-", dir="/tmp"))
    yield directory / "api.sock"
    shutil.rmtree(directory, ignore_errors=True)
