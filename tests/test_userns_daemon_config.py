"""The daemon.json merge keeps the operator's keys and refuses conflicts."""
from __future__ import annotations

import json

import pytest

from boxmunge.userns.daemon_config import DaemonConfigError, merged_daemon_json

REMAP = {"userns-remap": "boxmunge-remap:boxmunge-remap", "storage-driver": "overlay2"}


def test_no_file_gets_every_boxmunge_key() -> None:
    doc = json.loads(merged_daemon_json(None))
    assert doc == {"log-driver": "json-file", "log-opts": {"max-size": "50m", "max-file": "5"},
                   **REMAP, "features": {"containerd-snapshotter": False}}


def test_operator_keys_survive_and_the_merge_is_idempotent() -> None:
    raw = json.dumps({"registry-mirrors": ["https://m.example"], "log-opts": {"max-size": "9m"},
                      "features": {"buildkit": True}}).encode()
    once = merged_daemon_json(raw)
    doc = json.loads(once)
    assert doc["registry-mirrors"] == ["https://m.example"] and doc["log-opts"] == {"max-size": "9m"}
    assert doc["features"] == {"buildkit": True, "containerd-snapshotter": False}
    assert merged_daemon_json(once) == once


def test_an_explicit_overlay2_graph_driver_is_kept() -> None:
    raw = json.dumps({"storage-driver": "overlay2",
                      "features": {"containerd-snapshotter": False}}).encode()
    assert json.loads(merged_daemon_json(raw))["storage-driver"] == "overlay2"


@pytest.mark.parametrize("doc, named", [
    ({"data-root": "/srv/docker"}, "data-root"),
    ({"features": {"containerd-snapshotter": True}}, "containerd-snapshotter is true"),
    ({"storage-driver": "btrfs"}, "storage-driver"),
    ({"userns-remap": "default"}, "userns-remap is already"),
    ({"features": "on"}, "features is"),
])
def test_conflicts_are_refused_not_overwritten(doc, named) -> None:
    with pytest.raises(DaemonConfigError, match=named):
        merged_daemon_json(json.dumps(doc).encode())


@pytest.mark.parametrize("raw", [b"{not json", b"[1, 2]", b"\xff"])
def test_unreadable_daemon_json_is_refused(raw) -> None:
    with pytest.raises(DaemonConfigError):
        merged_daemon_json(raw)
