"""The package version must have exactly one effective source of truth.

`__version__` is what the handshake sends to the server, which compares it
against min_client_version. If it drifts from pyproject.toml, the CLI
misreports itself and a compatibility gate can pass or fail wrongly.
"""

import pathlib
import re

import boxmunge_cli


def _pyproject_version() -> str:
    text = (pathlib.Path(__file__).parent.parent / "pyproject.toml").read_text()
    match = re.search(r'^version = "([^"]+)"', text, re.MULTILINE)
    assert match, "no version found in cli/pyproject.toml"
    return match.group(1)


def test_dunder_version_matches_pyproject() -> None:
    assert boxmunge_cli.__version__ == _pyproject_version(), (
        f"__version__ is {boxmunge_cli.__version__!r} but pyproject.toml says "
        f"{_pyproject_version()!r}. The handshake sends __version__ to the "
        f"server, so drift misreports the client version."
    )
