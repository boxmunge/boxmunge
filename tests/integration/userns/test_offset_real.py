"""remap_offset against a real remapped daemon (dind)."""
from __future__ import annotations

import json
import subprocess

import pytest

from boxmunge.userns import offset
from tests.integration.userns.conftest import USERNS_DIND

pytestmark = USERNS_DIND


# The prior-daemon tests come first: remapped_daemon is module-scoped and
# stays switched from its first use to the end of the module.
def test_prior_daemon_reports_its_store() -> None:
    info = json.loads(subprocess.run(["docker", "info", "--format", "{{json .}}"],
                                     check=True, capture_output=True, text=True).stdout)
    assert "name=userns" not in info["SecurityOptions"]


def test_record_without_daemon_is_inconsistent(dind_paths) -> None:
    offset.write_offset_record(dind_paths, 1048576)
    with pytest.raises(offset.RemapError, match="not remapped"):
        offset.remap_offset(dind_paths)


def test_remapped_daemon_matches_the_record(dind_record, remapped_daemon) -> None:
    assert offset.remap_offset(dind_record) == remapped_daemon


def test_container_root_is_host_s(remapped_daemon, tmp_path) -> None:
    tmp_path.chmod(0o777)
    out = subprocess.run(
        ["docker", "run", "--rm", "-v", f"{tmp_path}:/x", "busybox:1.36",
         "sh", "-c", "cat /proc/self/uid_map && touch /x/f"],
        check=True, capture_output=True, text=True).stdout.split()
    assert out[:3] == ["0", str(remapped_daemon), "65536"]
    assert (tmp_path / "f").stat().st_uid == remapped_daemon
