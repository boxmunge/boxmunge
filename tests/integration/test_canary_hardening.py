"""Verify v0.5 hardening flags are actually applied to running containers.

Marked `integration` — requires Docker and the boxmunge platform installed.
Skipped automatically when not on a boxmunge VM.
"""
from __future__ import annotations

import json
import subprocess

import pytest


pytestmark = pytest.mark.integration


def _container_id_for(name: str) -> str:
    out = subprocess.check_output(
        ["docker", "ps", "-q", "-f", f"name={name}"], text=True
    ).strip()
    if not out:
        pytest.skip(f"Container {name} not running — canary not deployed.")
    return out.split("\n")[0]


def _inspect(container: str) -> dict:
    out = subprocess.check_output(
        ["docker", "inspect", container], text=True
    )
    return json.loads(out)[0]


def test_canary_web_has_no_new_privileges() -> None:
    """canary's `web` service must run with no-new-privileges."""
    cid = _container_id_for("canary-web")
    info = _inspect(cid)
    sec_opt = info["HostConfig"].get("SecurityOpt") or []
    assert any("no-new-privileges" in s for s in sec_opt), \
        f"no-new-privileges missing from {sec_opt!r}"


def test_canary_web_has_pids_limit() -> None:
    cid = _container_id_for("canary-web")
    info = _inspect(cid)
    pids = info["HostConfig"].get("PidsLimit")
    assert pids == 512, f"expected pids_limit=512, got {pids!r}"


def test_canary_web_drops_dangerous_caps() -> None:
    cid = _container_id_for("canary-web")
    info = _inspect(cid)
    cap_drop = info["HostConfig"].get("CapDrop") or []
    for cap in ("NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_RAW"):
        assert cap in cap_drop, f"{cap} missing from CapDrop {cap_drop!r}"


def test_canary_web_has_init_true() -> None:
    cid = _container_id_for("canary-web")
    info = _inspect(cid)
    assert info["HostConfig"].get("Init") is True, \
        "Init flag not set on canary-web"
