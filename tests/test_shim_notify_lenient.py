"""The upgrade shim's own alert loads the host config leniently.

notify_via runs in whichever venv slot it is handed, so it meets both a
load_config that takes `lenient_values` and, in a slot older than 0.11.9,
one that does not. The real shell function runs here against a stand-in
`boxmunge` package for each.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

SLOTS = Path(__file__).resolve().parent.parent / "scripts" / "boxmunge-upgrade.d" / "slots.sh"

CHECKS_VALUES = '''
class ConfigError(Exception):
    pass

def load_config(paths, *, lenient_values=False):
    if not lenient_values:
        raise ConfigError("'ssh_port' must be a whole number")
    return {"pushover": {"user_key": "u", "app_token": "t"}}
'''
OLDER_RELEASE = '''
def load_config(paths):
    return {"pushover": {"user_key": "u", "app_token": "t"}}
'''


def _venv_python(tmp_path: Path, config_module: str) -> Path:
    """A `python` whose boxmunge package is a stand-in with this config.py."""
    package = tmp_path / "site" / "boxmunge"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (package / "config.py").write_text(config_module)
    (package / "paths.py").write_text("class BoxPaths:\n    pass\n")
    (package / "pushover.py").write_text(
        "import pathlib\n"
        "def send_notification(user_key, app_token, title, message, priority=0):\n"
        f"    pathlib.Path({str(tmp_path / 'sent')!r}).write_text(title)\n"
        "    return True\n")
    python = tmp_path / "python"
    python.write_text(f"#!/bin/sh\nPYTHONPATH={package.parent} exec {sys.executable} \"$@\"\n")
    python.chmod(0o755)
    return python


@pytest.mark.parametrize("config_module", [CHECKS_VALUES, OLDER_RELEASE],
                         ids=["a slot that checks values", "a slot older than 0.11.9"])
def test_the_alert_is_sent_from_either_slot(tmp_path: Path, config_module: str) -> None:
    python = _venv_python(tmp_path, config_module)
    result = subprocess.run(
        ["bash", "-c", f'source "{SLOTS}"; notify_via "{python}" "upgrade rolled back" "body" 1'],
        capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "sent").read_text() == "upgrade rolled back"
