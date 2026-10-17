"""Upgrading into this release with an older release's shim leaves a working shim.

Older shims self-update by copying only the bundle's scripts/boxmunge-upgrade
into bin/ (v0.6.x shims never re-run install.sh at all; later ones re-run it
only when it changed, and it can fail). So the bundle's shim must be one
self-contained file. Each case builds the real bundle (`make bundle`), runs
shim_hop.sh as root in a throwaway container with a released old shim, and
checks the shim it leaves installed, and that the new shim, once installed,
waits for the old shim's upgrade (which locks only the legacy upgrade.lock).

The old shims in old_shims/ are copies of released files: v0.10.1 (the
latest release before the shim was split, identical to main at the time)
and v0.6.3 (from before the shim re-ran install.sh).
"""
from __future__ import annotations

import re
import subprocess
import tarfile
import uuid
from pathlib import Path

import pytest

from tests.integration.conftest import skip_no_docker

pytestmark = [pytest.mark.integration, skip_no_docker]

REPO = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
IMAGE = "python:3.13-slim"


@pytest.fixture(scope="module")
def bundle(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("bundle")
    tarball = out / "boxmunge.tar.gz"
    subprocess.run(["make", "-C", str(REPO), "bundle", f"BUNDLE={tarball}"],
                   check=True, capture_output=True, text=True)
    with tarfile.open(tarball) as tar:
        tar.extractall(out, filter="tar")
    return out


def _hop(bundle: Path, mode: str, old_shim: str) -> dict[str, str]:
    result = subprocess.run(
        ["docker", "run", "--rm", "--name", f"bmtest-shim-hop-{uuid.uuid4().hex[:10]}",
         "-v", f"{bundle}:/bundle:ro", "-v", f"{HERE}:/t:ro",
         IMAGE, "bash", "/t/shim_hop.sh", mode, f"/t/old_shims/{old_shim}"],
        capture_output=True, text=True, timeout=600, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    facts = dict(re.findall(r"^([A-Z_]+)=(\S+)$", result.stdout, re.M))
    facts["hop_rc"] = re.search(r"^HOP rc=(\d+)$", result.stdout, re.M).group(1)
    for name, rc, out in re.findall(r"^CMD (\S+) rc=(\d+) :: (.*)$", result.stdout, re.M):
        facts[f"{name}_rc"], facts[f"{name}_out"] = rc, out
    for name, rc, out in re.findall(r"^DURING (\S+) rc=(\d+) :: (.*)$", result.stdout, re.M):
        facts[f"during_{name}_rc"], facts[f"during_{name}_out"] = rc, out
    facts["log"] = result.stdout
    return facts


def test_bundle_ships_one_self_contained_shim(bundle: Path) -> None:
    scripts = bundle / "boxmunge" / "scripts"
    assert not (scripts / "boxmunge-upgrade.d").exists()
    assert not re.search(r"^# >>> boxmunge-upgrade\.d:", (scripts / "boxmunge-upgrade").read_text(), re.M)


@pytest.mark.parametrize(("old_shim", "mode"), [
    ("boxmunge-upgrade-v0.10.1", "ok"),
    ("boxmunge-upgrade-v0.10.1", "fail"),
    ("boxmunge-upgrade-v0.6.3", "ok"),
    ("boxmunge-upgrade-v0.6.3", "fail"),
])
def test_old_shim_hop_leaves_a_working_shim(bundle: Path, old_shim: str, mode: str) -> None:
    facts = _hop(bundle, mode, old_shim)
    log = facts["log"]
    assert facts["SHIM_IS_BUNDLED"] == "yes", log
    # What a missing library looks like: the source loader's refusal, or a
    # function that was never defined.
    assert "unbuilt source shim" not in log and "command not found" not in log, log
    assert facts["check-probation_rc"] == "0", log
    # v0.6.3 never runs install.sh, so its upgrade completes whatever the
    # stand-in would do; v0.10.1 aborts before the swap when install.sh fails.
    upgraded = mode == "ok" or old_shim.endswith("v0.6.3")
    if upgraded:
        assert facts["hop_rc"] == "0", log
        # Mid-hop, the old shim holds only the legacy lock; the new shim it
        # installed must not start a second upgrade or act on probation.
        assert facts["during_target_rc"] == "1", log
        assert "Another upgrade is in progress" in facts["during_target_out"], log
        assert facts["during_check-probation_rc"] == "0", log
        assert "Another upgrade is in progress; skipping" in facts["during_check-probation_out"], log
        assert facts["LIVE"] == "/opt/boxmunge/env-b" and facts["PROBATION"] == "yes", log
        # The new shim honours the probation the old one started.
        assert facts["run_rc"] == "0" and "is on probation" in facts["run_out"], log
        assert facts["target_rc"] == "1" and "is on probation" in facts["target_out"], log
    else:
        assert facts["hop_rc"] == "1", log
        assert facts["LIVE"] == "/opt/boxmunge/env-a" and facts["PROBATION"] == "no", log
        # Upgrades still run: this one gets as far as the (absent) download.
        assert "Failed to download bundle" in facts["target_out"], log
    if mode == "ok" and not old_shim.endswith("v0.6.3"):
        assert facts["LEFTOVER_LIBS"] == "no", log
