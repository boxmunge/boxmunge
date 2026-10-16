# SPDX-License-Identifier: Apache-2.0
"""Fixtures for the action API tests."""
from __future__ import annotations

from pathlib import Path

import pytest

from boxmunge.api.dev.fixture import make_fixture
from boxmunge.paths import BoxPaths


@pytest.fixture
def fixture_paths(tmp_path: Path) -> BoxPaths:
    """A freshly written dev fixture box, timestamps relative to now."""
    return make_fixture(tmp_path / "box")
