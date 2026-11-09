# SPDX-License-Identifier: Apache-2.0
"""Snapshots and backup keys made by an older system image still work.

Boxes keep their backup key and their old snapshots across an upgrade of the
system image's age (1.2.1 up to boxmunge 0.11.3). tests/fixtures/age-v1.2.1
holds an identity made by age-keygen v1.2.1 and a snapshot it encrypted, as
backup.encrypt_file does (`age --encrypt -r <recipient>`). This decrypts it
with the age in the real system image, through the running container.
"""
from __future__ import annotations

import hashlib
import shutil
import uuid
from pathlib import Path

import pytest

import boxmunge.system_container as sc
from boxmunge.paths import BoxPaths

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("system_container")]

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "age-v1.2.1"


@pytest.fixture
def backups(int_paths: BoxPaths):
    bdir = int_paths.project_backups(f"agecompat-{uuid.uuid4().hex[:6]}")
    bdir.mkdir(parents=True)
    for name in ("identity.txt", "snapshot.tar.gz.age"):
        shutil.copy(FIXTURE / name, bdir / name)
    try:
        yield bdir
    finally:
        shutil.rmtree(bdir.parent)


def test_a_snapshot_encrypted_by_age_1_2_decrypts(int_paths: BoxPaths, backups: Path) -> None:
    tools = sc.connect(int_paths)
    out = backups / "snapshot.tar.gz"
    tools.run(["age", "--decrypt", "-i", tools.path(backups / "identity.txt"),
               "-o", tools.path(out), tools.path(backups / "snapshot.tar.gz.age")])
    expected = (FIXTURE / "snapshot.tar.gz.sha256").read_text().split()[0]
    assert hashlib.sha256(out.read_bytes()).hexdigest() == expected


def test_a_key_made_by_age_1_2_gives_the_same_recipient(int_paths: BoxPaths, backups: Path) -> None:
    """backup._read_recipient falls back to `age-keygen -y` for a key file
    without the public-key comment."""
    tools = sc.connect(int_paths)
    recipient = tools.run(["age-keygen", "-y", tools.path(backups / "identity.txt")]).stdout.strip()
    assert f"# public key: {recipient}\n" in (FIXTURE / "identity.txt").read_text()
