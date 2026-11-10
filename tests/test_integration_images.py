# SPDX-License-Identifier: Apache-2.0
"""tests/integration/images.py: every registry image an integration module
names is declared, so the integration conftest pulls it before the module
runs, whichever shard (and whichever modules before it) CI gives it."""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.integration.images import (
    HERE, IMAGES, NOT_IMAGES, image_like, named_by, scanned_files,
)


def test_every_image_like_reference_is_declared_one_way_or_the_other() -> None:
    unknown = {}
    for path in scanned_files():
        for ref in image_like(path.read_text()) - IMAGES - NOT_IMAGES:
            unknown.setdefault(ref, path.relative_to(HERE).as_posix())
    assert unknown == {}, ("name each in tests/integration/images.py: IMAGES if the tests "
                           f"need it pulled, NOT_IMAGES if it is no image to pull: {unknown}")


def test_no_declaration_is_stale() -> None:
    named = {ref for path in scanned_files() for ref in image_like(path.read_text())}
    assert IMAGES - named == set() and NOT_IMAGES - named == set()
    assert IMAGES & NOT_IMAGES == set()


@pytest.mark.parametrize("module, image", [
    ("test_dump_offline.py", "alpine:3.20"),          # its own compose file
    ("test_nonroot_deploy.py", "mysql:8.4"),          # through nonroot_cases.py
    ("test_legacy_upgrade.py", "busybox:1.36"),       # through docker_images.py
    ("test_backup_restore.py", "postgres:16-alpine"),  # conftest.py's fixture_project
])
def test_a_module_gets_the_images_it_names_however_it_names_them(module: str,
                                                                 image: str) -> None:
    assert image in named_by(HERE / module)


def test_every_integration_module_is_covered() -> None:
    modules = sorted(Path(HERE).glob("test_*.py"))
    assert modules and all(isinstance(named_by(m), set) for m in modules)
