# SPDX-License-Identifier: Apache-2.0
"""scripts/release-lint.py loaded as a module, and the files to point it at
(releases.json, pyproject.toml, an upgrade-notes directory and an
upgrade_floor.py), for the release workflow's tests."""
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


def _key(version: str) -> tuple[int, ...]:
    return tuple(int(n) for n in version.split("."))


def write_notes(notes_dir: Path, version: str, doc: dict | None = None) -> Path:
    """upgrade-notes/<version>.json; by default a no-project-action marker."""
    notes_dir.mkdir(parents=True, exist_ok=True)
    path = notes_dir / f"{version}.json"
    path.write_text(json.dumps(doc or {"version": version, "no_project_action": True,
                                       "entries": []}))
    return path


def write_tree(tmp_path: Path, version: str, releases: list[tuple]) -> dict:
    """releases: (version, class) or (version, class, breaking) tuples. The
    notes directory holds a no-project-action file for `version`, and the
    floor module puts floor and bridge at the oldest version named."""
    releases_json = tmp_path / "releases.json"
    releases_json.write_text(json.dumps({"releases": [
        {"version": r[0], "class": r[1], "breaking": r[2] if len(r) > 2 else False,
         "url": f"{GH}{r[0]}"}
        for r in releases
    ]}))
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(f'[project]\nname = "boxmunge-server"\nversion = "{version}"\n')
    notes = tmp_path / "upgrade-notes"
    write_notes(notes, version)
    oldest = min([version, *(r[0] for r in releases)], key=_key)
    floor = tmp_path / "upgrade_floor.py"
    floor.write_text(f'UPGRADE_FLOOR = "{oldest}"\nBRIDGE_RELEASE = "{oldest}"\n')
    return {"releases": releases_json, "pyproject": pyproject, "notes": notes,
            "floor": floor}
