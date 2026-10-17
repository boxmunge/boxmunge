# SPDX-License-Identifier: Apache-2.0
"""Fixtures shared by the legacy-stage command tests."""
from __future__ import annotations

import pytest

from tests.bundle_helpers import SAFE_COMPOSE
from tests.legacy_helpers import legacy_bundle_stage, legacy_git_stage, reflog_checkout_time, stamp
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
