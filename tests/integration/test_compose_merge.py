"""Integration: docker compose merge precedence + hostile-compose rejection.

These tests are the smoke tests that would have caught audit Finding 6 — if
the merged compose result silently lacks the boxmunge baseline (cap_drop /
security_opt), or if a hostile compose.yml is allowed through, the silent
floor claim is unsubstantiated.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from boxmunge.compose_validate import ComposeSecurityError, validate_user_compose
from boxmunge.paths import BoxPaths


pytestmark = pytest.mark.integration


def _docker_on_path() -> bool:
    return shutil.which("docker") is not None


skip_no_docker = pytest.mark.skipif(
    not _docker_on_path(), reason="docker CLI not on PATH",
)


_BENIGN_COMPOSE = """\
services:
  web:
    image: nginx:alpine
    ports:
      - "8080:80"
"""

# Mirror of the boxmunge default-profile overlay for a single service.
# Mirrors security_overlay._baseline_for_profile + render_compose_security_fragment.
_BOXMUNGE_OVERLAY = """\
services:
  web:
    security_opt:
      - no-new-privileges:true
    init: true
    pids_limit: 512
    cap_drop:
      - NET_ADMIN
      - SYS_PTRACE
      - SYS_MODULE
      - SYS_RAWIO
      - SYS_TIME
      - SYS_BOOT
      - MAC_ADMIN
      - MAC_OVERRIDE
      - MKNOD
      - AUDIT_WRITE
      - WAKE_ALARM
      - BLOCK_SUSPEND
      - LEASE
      - NET_RAW
"""

_HOSTILE_COMPOSE = """\
services:
  web:
    image: nginx:alpine
    privileged: true
"""


@skip_no_docker
def test_benign_compose_merge_preserves_overlay(tmp_path: Path) -> None:
    """Confirm Compose's multi-file merge keeps the boxmunge overlay's
    cap_drop and security_opt for a benign user compose.yml.

    This is the empirical check that the silent floor actually applies.
    """
    (tmp_path / "compose.yml").write_text(_BENIGN_COMPOSE)
    (tmp_path / "compose.boxmunge.yml").write_text(_BOXMUNGE_OVERLAY)

    result = subprocess.run(
        [
            "docker", "compose",
            "-f", "compose.yml",
            "-f", "compose.boxmunge.yml",
            "config", "--format", "json",
        ],
        cwd=tmp_path, capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        pytest.fail(
            f"docker compose config failed: rc={result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    merged = json.loads(result.stdout)
    web = merged["services"]["web"]

    # cap_drop must include NET_ADMIN (and others from DEFAULT_CAP_DROP).
    cap_drop = web.get("cap_drop") or []
    assert "NET_ADMIN" in cap_drop, f"NET_ADMIN missing from merged cap_drop: {cap_drop}"
    assert "NET_RAW" in cap_drop

    # security_opt must include no-new-privileges:true.
    sec_opt = web.get("security_opt") or []
    assert any("no-new-privileges" in s and "true" in s for s in sec_opt), (
        f"no-new-privileges missing from merged security_opt: {sec_opt}"
    )


def test_hostile_compose_rejected_before_merge(tmp_path: Path) -> None:
    """Confirm validate_user_compose rejects privileged: true.

    Doesn't need docker — the validator runs before docker compose config
    is invoked, which is precisely the point of audit Finding 6's fix.
    """
    compose_path = tmp_path / "compose.yml"
    compose_path.write_text(_HOSTILE_COMPOSE)
    paths = BoxPaths(root=tmp_path)

    with pytest.raises(ComposeSecurityError, match="privileged"):
        validate_user_compose(compose_path, paths)
