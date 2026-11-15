# SPDX-License-Identifier: Apache-2.0
"""lock_attempts: project_lock replaced by a function that records the
attempt and raises, so code that must never take the project lock (an
operate core, an action handler the job worker runs) fails the test if it
reaches for it, even if the error is swallowed."""
from __future__ import annotations

import sys

import pytest

from boxmunge import fileutil


@pytest.fixture
def lock_attempts(monkeypatch) -> list[str]:
    """Replace project_lock in every loaded boxmunge module."""
    attempts: list[str] = []

    def forbidden(name, paths):
        attempts.append(name)
        raise AssertionError(f"an operate core took the project lock for {name!r}")

    real = fileutil.project_lock
    patched = []
    for module in list(sys.modules.values()):
        if (getattr(module, "__name__", "").startswith("boxmunge")
                and getattr(module, "project_lock", None) is real):
            patched.append(module.__name__)
            monkeypatch.setattr(module, "project_lock", forbidden)
    assert "boxmunge.commands.deploy" in patched and "boxmunge.fileutil" in patched
    yield attempts
    assert attempts == [], "a core acquired the project lock"
