# SPDX-License-Identifier: Apache-2.0
"""Give a manifest its project id (ULID) without re-serialising the file.

The id is fixed once, normally by `boxmunge init`. When a manifest has no id
(hand-written, or `id: null`), `bundle` adds one by editing a single line of
text: comments, ordering and quoting are left exactly as the user wrote them.
The write is atomic and keeps the file's mode.
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

import yaml

from boxmunge_cli.ulid import generate_ulid

# A top-level `id:` key whose value is empty or null, with an optional comment.
_EMPTY_ID_LINE = re.compile(
    r"^id:[ \t]*(?:null|Null|NULL|~|''|\"\")?[ \t]*(?:#.*)?$", re.MULTILINE
)


class ManifestIdError(Exception):
    """Raised when the id cannot be added safely."""


def _with_id(text: str, ulid: str) -> str:
    matches = list(_EMPTY_ID_LINE.finditer(text))
    if len(matches) > 1:
        raise ManifestIdError("manifest.yml has more than one top-level 'id:' line.")
    if matches:
        m = matches[0]
        return text[: m.start()] + f"id: {ulid}" + text[m.end():]
    if re.search(r"^id:", text, re.MULTILINE):
        raise ManifestIdError(
            "manifest.yml has an 'id:' line this client cannot rewrite safely. "
            "Set it by hand to a ULID, or remove the line and bundle again."
        )
    if text.startswith("---\n"):
        return "---\n" + f"id: {ulid}\n" + text[4:]
    return f"id: {ulid}\n" + text


def _atomic_write(path: Path, text: str) -> None:
    mode = path.stat().st_mode & 0o7777
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".manifest.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def add_manifest_id(manifest_path: Path) -> str:
    """Write a new ULID into manifest_path and return it.

    Raises ManifestIdError if the edited file does not parse back to the same
    data plus the new id, so a bad edit never reaches disk.
    """
    text = manifest_path.read_text(encoding="utf-8")
    ulid = generate_ulid()
    new_text = _with_id(text, ulid)

    before = yaml.safe_load(text)
    after = yaml.safe_load(new_text)
    expected = dict(before) if isinstance(before, dict) else {}
    expected["id"] = ulid
    if after != expected:
        raise ManifestIdError(
            "Adding the id to manifest.yml would change other fields. "
            f"Add 'id: {ulid}' as the first line by hand."
        )
    _atomic_write(manifest_path, new_text)
    return ulid
