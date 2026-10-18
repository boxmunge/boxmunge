# SPDX-License-Identifier: Apache-2.0
"""daemon.json for a remapped daemon: a merge that keeps the operator's keys.

The remap keys are written explicitly. Docker 29 silently falls back from
the containerd image store to the graph driver under userns-remap, and a
later Docker that allowed the snapshotter there would switch stores at the
next restart, so `containerd-snapshotter: false` is pinned; `storage-driver:
overlay2` makes a host without overlay support fail loudly instead of
falling back to vfs. A conflicting key is refused, never overwritten.
"""
from __future__ import annotations

import json
from typing import Any

from boxmunge.userns.offset import DAEMON_REMAP_VALUE

DEFAULT_DATA_ROOT = "/var/lib/docker"
_LOG_KEYS: dict[str, Any] = {"log-driver": "json-file",
                             "log-opts": {"max-size": "50m", "max-file": "5"}}


class DaemonConfigError(Exception):
    """daemon.json cannot be read, or holds a key the remap conflicts with."""


def parse_daemon_json(raw: bytes | None) -> dict[str, Any]:
    if raw is None or not raw.strip():
        return {}
    try:
        doc = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise DaemonConfigError(f"daemon.json is not valid JSON: {e}") from e
    if not isinstance(doc, dict):
        raise DaemonConfigError("daemon.json is not a JSON object")
    return doc


def conflicts(doc: dict[str, Any]) -> list[str]:
    out = []
    if doc.get("data-root", DEFAULT_DATA_ROOT) != DEFAULT_DATA_ROOT:
        out.append(f"data-root is {doc['data-root']!r}; the migration supports only "
                   f"{DEFAULT_DATA_ROOT}")
    features = doc.get("features", {})
    if not isinstance(features, dict):
        out.append(f"features is {features!r}, not an object")
    elif features.get("containerd-snapshotter") is True:
        out.append("features.containerd-snapshotter is true, which Docker refuses to "
                   "combine with userns-remap")
    if doc.get("storage-driver", "overlay2") != "overlay2":
        out.append(f"storage-driver is {doc['storage-driver']!r}, not overlay2")
    if doc.get("userns-remap", DAEMON_REMAP_VALUE) != DAEMON_REMAP_VALUE:
        out.append(f"userns-remap is already {doc['userns-remap']!r}")
    return out


def merged_daemon_json(raw: bytes | None) -> bytes:
    """The remapped daemon.json for `raw` (None: no file). Raises DaemonConfigError."""
    doc = parse_daemon_json(raw)
    problems = conflicts(doc)
    if problems:
        raise DaemonConfigError("daemon.json cannot be remapped as it is: " + "; ".join(problems))
    merged = {**_LOG_KEYS, **doc,
              "userns-remap": DAEMON_REMAP_VALUE, "storage-driver": "overlay2",
              "features": {**doc.get("features", {}), "containerd-snapshotter": False}}
    return (json.dumps(merged, indent=4) + "\n").encode()
