# SPDX-License-Identifier: Apache-2.0
"""Compiled upgrade-notes.json documents for the deploy-side tests."""
from __future__ import annotations

import json
from typing import Any


def entry(introduced: str, slug: str, scope: str = "project", when: str = "before", *,
          kind: str = "required", files: list[str] | None = None,
          change: str = "Change this.\nThen that.", verify: str = "Check it.") -> dict[str, Any]:
    return {"introduced": introduced, "id": f"{introduced}-{slug}", "scope": scope,
            "when": when, "kind": kind, "title": f"Title of {slug}", "change": change,
            "verify": verify,
            "files": files if files is not None else (["manifest.yml"] if scope == "project"
                                                      else []),
            "superseded_by": None, "refs": []}


def notes_doc(release: str = "0.12.0", entries: list[dict] | None = None, *,
              no_action: tuple[str, ...] = ("0.11.9",), floor: str = "0.11.0",
              bridge: str = "0.11.6") -> dict[str, Any]:
    versions = {floor, bridge, release, *no_action,
                *(e["introduced"] for e in entries or [])}
    return {"format": 1, "release": release, "floor": floor, "bridge": bridge,
            "releases": {v: {"class": "feature", "breaking": v == release} for v in versions},
            "no_action": list(no_action), "entries": entries or []}


def notes_bytes(*args: Any, **kwargs: Any) -> bytes:
    return (json.dumps(notes_doc(*args, **kwargs), indent=2) + "\n").encode()
