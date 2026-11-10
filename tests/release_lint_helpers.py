# SPDX-License-Identifier: Apache-2.0
"""scripts/release-lint.py loaded as a module, and a releases.json and
pyproject.toml pair to point it at, for the release workflow's tests."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "release-lint.py"
GH = "https://github.com/boxmunge/boxmunge/releases/tag/v"


def _load_module():
    spec = importlib.util.spec_from_file_location("release_lint", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve their module by name
    spec.loader.exec_module(module)
    return module


lint = _load_module()


def write_tree(tmp_path: Path, version: str, releases: list[tuple]) -> dict:
    """releases: (version, class) or (version, class, breaking) tuples."""
    releases_json = tmp_path / "releases.json"
    releases_json.write_text(json.dumps({"releases": [
        {"version": r[0], "class": r[1], "breaking": r[2] if len(r) > 2 else False,
         "url": f"{GH}{r[0]}"}
        for r in releases
    ]}))
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(f'[project]\nname = "boxmunge-server"\nversion = "{version}"\n')
    return {"releases": releases_json, "pyproject": pyproject}
