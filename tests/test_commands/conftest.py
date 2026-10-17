# SPDX-License-Identifier: Apache-2.0
"""Fixtures shared by the legacy-stage command tests."""
from __future__ import annotations

import json

import pytest

from boxmunge.legacy_stage import legacy_staging_state
from tests.bundle_helpers import SAFE_COMPOSE
from tests.legacy_helpers import legacy_bundle_stage, legacy_git_stage, reflog_checkout_time, stamp
from tests.stage_helpers import V2
from tests.test_legacy_stage_evidence import T


@pytest.fixture
def legacy(paths):
    """A bundle project with a 0.10.1 stage made at T."""
    pdir = legacy_bundle_stage(paths)
    stamp(pdir / ".releases" / "prestage" / "meta.json", T)
    return pdir


@pytest.fixture
def legacy_git(paths, tmp_path):
    """A git project deployed at A with a 0.10.1 stage of B: (A, B, repo, T)."""
    (tmp_path / "src").mkdir()
    a, b = legacy_git_stage(paths, tmp_path / "src")
    (paths.project_dir("myapp") / "compose.yml").write_text(SAFE_COMPOSE)
    repo = paths.project_dir("myapp") / "repo"
    return a, b, repo, reflog_checkout_time(repo)


@pytest.fixture
def never_deployed(paths):
    """0.10.1 staged a bundle project that was never deployed: prestage ref
    null. Returns the project dir."""
    from boxmunge.project_registry import add_project
    from boxmunge.release import mark_live
    from tests.bundle_helpers import manifest_text
    add_project("myapp", paths)
    pdir = paths.project_dir("myapp")
    (pdir / ".releases" / "prestage" / "release").mkdir(parents=True)
    meta = pdir / ".releases" / "prestage" / "meta.json"
    meta.write_text(json.dumps({"ref": None}) + "\n")
    stamp(meta, T)
    for name, text in {"VERSION": "v2\n", "manifest.yml": manifest_text(),
                       "compose.yml": SAFE_COMPOSE,
                       "compose.boxmunge-staging.yml": "services: {}\n"}.items():
        (pdir / name).write_text(text)
    mark_live(paths, "myapp", f"myapp-{V2}")
    state = legacy_staging_state(paths, "myapp")
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(json.dumps({"active": True, "ref": f"myapp-{V2}"}))
    return pdir
