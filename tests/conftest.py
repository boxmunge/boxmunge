"""Shared test fixtures for boxmunge tests."""

import pytest
from pathlib import Path

from boxmunge.paths import BoxPaths


@pytest.fixture
def tmp_root(tmp_path: Path) -> Path:
    """Create a temporary boxmunge root directory with standard structure."""
    root = tmp_path / "boxmunge"
    for subdir in [
        "bin", "config", "caddy/sites", "projects", "state/health",
        "state/deploy", "state/staging", "templates/project", "docs", "logs",
        "inbox/.tmp", "inbox/.consumed",
    ]:
        (root / subdir).mkdir(parents=True)
    return root


@pytest.fixture
def paths(tmp_root: Path) -> BoxPaths:
    """BoxPaths pointing at a temporary root."""
    return BoxPaths(root=tmp_root)
