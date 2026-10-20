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
# The containerd a daemon uses, as `docker info` reports it: dockerd's own
# (started, or embedded, under its exec-root) or the system one Docker's
# packages run as a service. A remapped daemon whose containerd namespace is
# not set explicitly uses moby-<uid>.<gid> beside the old daemon's moby.
MANAGED_CONTAINERD = frozenset({"/var/run/docker/containerd/containerd.sock",
                                "/run/docker/containerd/containerd.sock"})
SYSTEM_CONTAINERD = frozenset({"/run/containerd/containerd.sock",
                               "/var/run/containerd/containerd.sock"})
SYSTEM_CONTAINERD_ROOT = "/var/lib/containerd"
DEFAULT_NAMESPACE = "moby"
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


def containerd_refusals(doc: dict[str, Any]) -> list[str]:
    """Keys the migration refuses to start with (preflight only: a rollback
    gives back the journalled daemon.json whatever it holds)."""
    out = []
    if "containerd-namespace" in doc:
        out.append(f"containerd-namespace is set ({doc['containerd-namespace']!r}): a "
                   f"remapped daemon would share that namespace with the old one, and "
                   f"userns-commit could not tell the old images from the live ones; remove it")
    if "containerd" in doc and doc["containerd"] not in SYSTEM_CONTAINERD:
        out.append(f"containerd is {doc['containerd']!r}; the migration supports dockerd's own "
                   f"containerd or the system one at "
                   f"{' or '.join(sorted(SYSTEM_CONTAINERD))}; remove it or point it there")
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
