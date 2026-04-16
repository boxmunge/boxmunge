"""Shared test fixtures for boxmunge CLI tests."""

import pytest
from pathlib import Path


@pytest.fixture
def tmp_project(tmp_path: Path) -> Path:
    """Create a temporary project directory."""
    return tmp_path / "myproject"


@pytest.fixture
def boxmunge_config(tmp_path: Path) -> Path:
    """Write a valid .boxmunge config and return the directory."""
    config = tmp_path / "myproject"
    config.mkdir()
    (config / ".boxmunge").write_text(
        "server: box.example.com\nport: 922\nuser: deploy\nproject: myapp\n"
    )
    return config
