"""An older release's shim meets this release: refused below the upgrade
floor, and left a working shim above it.

Each case builds the real bundle (`make bundle`) and runs shim_hop.sh as root
in a throwaway container with a released old shim. The image holds this
tree's package installed in a venv, so the pre-flight the old shim runs (its
import test, `--version`, `upgrade --dry-run`) is the real one: a failure
there blocklists the release before the old shim stashes, installs the new
shim or runs install.sh.

Below the floor, that is where the release refuses, and all it can tell the
operator is what the pre-flight prints. The box must be left on its release
with its own shim, and still able to take the bridge release the refusal
names.

At the floor the hop completes. Older shims self-update by copying only the
bundle's scripts/boxmunge-upgrade into bin/, and install.sh can fail, so the
bundle's shim must be one self-contained file; the new shim, once installed,
must wait for the old shim's upgrade and honour the probation it starts. A
hop whose apply fails after the swap is rolled back by the old shim, which
must take away the units this release added and put back the ones it
retired: that is why the floor is 0.11.11, the first shim that does.

The old shims in old_shims/ are released files. Below the floor: v0.11.10
(the shim of the release before the floor) and v0.11.0, each tag's
`scripts/build-shim.py` output; v0.10.1; v0.10.0 (byte for byte the shim
every release from v0.9.2 to v0.10.0 shipped, so also that of a box on
v0.9.16); v0.9.1 (the shim of every release from v0.7.0 to v0.9.1, whose
import test reads `boxmunge.__version__`); and v0.6.3 (the same import test,
and it never runs install.sh). At the floor: v0.11.11, extracted from the
published release bundle (its SHA256SUMS checked), the shim of the floor and
bridge release, which every box below the floor arrives with.

The bridge release here is a stand-in that ships the real v0.11.11 shim: its
own pre-flight is not run. A box below 0.11.0 told to install it is refused
by the real 0.11.11 in turn, which names 0.11.6 (tests/test_upgrade_floor.py
of that release).

The image has sudo, so each sudo rule a shim writes is checked by the real
visudo.
"""
from __future__ import annotations

import functools
import re
import subprocess
import tarfile
import uuid
from pathlib import Path
from typing import Iterator

import pytest

from boxmunge.upgrade_floor import BRIDGE_COMMAND, BRIDGE_RELEASE
from tests.integration.conftest import skip_no_docker

pytestmark = [pytest.mark.integration, skip_no_docker]

REPO = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
BASE = "python:3.13-slim"
# The release under test: this tree, numbered as the release it becomes.
NEW = "0.12.0"
# deploy's sudo rule as this release's shim writes it (sudoers_rule).
SHIM = "/opt/boxmunge/bin/boxmunge-upgrade"
RULE = (f"deploy ALL=(root) NOPASSWD: {SHIM} auto, {SHIM} target *, {SHIM} repair-deps, "
        f"{SHIM} check *, {SHIM} guide *")
PREPARE = f"""set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends sudo >/dev/null
cp -R /bundle/boxmunge /relsrc
sed -i 's/^version = ".*"$/version = "{NEW}"/' /relsrc/pyproject.toml
python3 -m venv /relvenv
/relvenv/bin/pip -q install /relsrc
"""


def _docker(*args: str, timeout: int = 600) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True,
                          timeout=timeout, check=False)


@pytest.fixture(scope="module")
def bundle(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("bundle")
    tarball = out / "boxmunge.tar.gz"
    subprocess.run(["make", "-C", str(REPO), "bundle", f"BUNDLE={tarball}"],
                   check=True, capture_output=True, text=True)
    with tarfile.open(tarball) as tar:
        tar.extractall(out, filter="tar")
    return out


@pytest.fixture(scope="module")
def image(bundle: Path) -> Iterator[str]:
    """BASE plus /relvenv: this tree's bundle, pip-installed as release NEW."""
    tag = f"bmtest-shim-hop-{uuid.uuid4().hex[:10]}:prepared"
    builder = f"bmtest-shim-hop-prep-{uuid.uuid4().hex[:10]}"
    try:
        made = _docker("run", "--name", builder, "-v", f"{bundle}:/bundle:ro",
                       BASE, "bash", "-c", PREPARE, timeout=900)
        assert made.returncode == 0, made.stdout + made.stderr
        committed = _docker("commit", builder, tag)
        assert committed.returncode == 0, committed.stderr
    finally:
        _docker("rm", "-f", builder)
    yield tag
    _docker("image", "rm", "-f", tag)


@functools.cache
def _hop(bundle: Path, image: str, mode: str, old_shim: str, installed: str) -> dict[str, str]:
    """The facts shim_hop.sh reports, once per hop (tests only read them)."""
    runner = f"bmtest-shim-hop-{uuid.uuid4().hex[:10]}"
    try:
        result = _docker("run", "--rm", "--name", runner,
                         "-v", f"{bundle}:/bundle:ro", "-v", f"{HERE}:/t:ro", image,
                         "bash", "/t/shim_hop.sh", mode, f"/t/old_shims/{old_shim}", installed)
    finally:
        _docker("rm", "-f", runner)
    assert result.returncode == 0, result.stdout + result.stderr
    facts = dict(re.findall(r"^([A-Z_]+)=(\S+)$", result.stdout, re.M))
    for step, rc in re.findall(r"^(HOP|BRIDGE|CLEAR) rc=(\d+)$", result.stdout, re.M):
        facts[f"{step.lower()}_rc"] = rc
    assert "hop_rc" in facts, result.stdout
    for name, rc, out in re.findall(r"^CMD (\S+) rc=(\d+) :: (.*)$", result.stdout, re.M):
        facts[f"{name}_rc"], facts[f"{name}_out"] = rc, out
    for name, rc, out in re.findall(r"^DURING (\S+) rc=(\d+) :: (.*)$", result.stdout, re.M):
        facts[f"during_{name}_rc"], facts[f"during_{name}_out"] = rc, out
    for name, text in re.findall(r"^--- (sudoers [a-z-]+)\n(.*?)(?=^--- )", result.stdout, re.M | re.S):
        facts[name.replace(" ", "_").replace("-", "_")] = text
    facts["log"] = result.stdout
    return facts


def test_bundle_ships_one_self_contained_shim(bundle: Path) -> None:
    scripts = bundle / "boxmunge" / "scripts"
    assert not (scripts / "boxmunge-upgrade.d").exists()
    assert not re.search(r"^# >>> boxmunge-upgrade\.d:", (scripts / "boxmunge-upgrade").read_text(), re.M)


@pytest.mark.parametrize(("old_shim", "installed", "stopped_at"), [
    ("boxmunge-upgrade-v0.11.10", "0.11.10", "dry-run upgrade"),
    ("boxmunge-upgrade-v0.11.0", "0.11.0", "dry-run upgrade"),
    ("boxmunge-upgrade-v0.10.1", "0.10.1", "dry-run upgrade"),
    ("boxmunge-upgrade-v0.10.0", "0.10.0", "dry-run upgrade"),
    ("boxmunge-upgrade-v0.10.0", "0.9.16", "dry-run upgrade"),
    ("boxmunge-upgrade-v0.9.1", "0.9.1", "import test"),
    ("boxmunge-upgrade-v0.6.3", "0.6.3", "import test"),
])
def test_below_the_floor_the_release_is_refused_and_the_bridge_release_still_installs(
        bundle: Path, image: str, old_shim: str, installed: str, stopped_at: str) -> None:
    facts = _hop(bundle, image, "floor", old_shim, installed)
    log = facts["log"]
    refusal = log.split("--- hop log\n")[1].split("--- bridge log\n")[0]
    # The operator is told, in the old shim's own output, by the one step of
    # that shim's pre-flight this release can fail.
    assert BRIDGE_COMMAND in refusal, log
    assert f"sudo /opt/boxmunge/bin/boxmunge-upgrade clear-blocklist {NEW}" in refusal, log
    assert refusal.rstrip().endswith(f"Pre-flight FAILED: {stopped_at}"), log
    if stopped_at == "dry-run upgrade":
        assert f"boxmunge {NEW} cannot be installed over {installed}" in refusal, log
    # The box is as it was: its release live, its own shim, nothing installed
    # into the live venv, install.sh never run, no probation.
    assert facts["hop_rc"] == "1", log
    assert facts["SHIM_IS"] == old_shim, log
    assert facts["LIVE"] == "/opt/boxmunge/env-a" and facts["PROBATION"] == "no", log
    assert facts["INSTALL_SH_RAN"] == "no" and facts["ENV_A_PIP_CALLS"] == "0", log
    assert facts["VERSION_RECORD"] == f"{installed}+abc1234", log
    # Only the refused release is blocklisted, so the command the refusal
    # names runs to the end with that same shim, and installs the bridge
    # release's own.
    assert facts["BLOCKLIST"] == NEW, log
    assert facts["bridge_rc"] == "0", log
    assert facts["BRIDGE_LIVE"] == "/opt/boxmunge/env-b" and facts["BRIDGE_PROBATION"] == "yes", log
    assert facts["BRIDGE_VERSION_RECORD"] == f"{BRIDGE_RELEASE}+abc1234", log
    assert facts["BRIDGE_SHIM_IS_THE_BRIDGE_RELEASES"] == "yes", log
    # Then the blocklist entry the refusal left is cleared as it said.
    assert facts["clear_rc"] == "0" and facts["CLEARED_BLOCKLIST"] == "none", log


FLOOR_SHIM = ("boxmunge-upgrade-v0.11.11", "0.11.11")
# The units this release adds, and the timers it retires (shim_hop.sh's box
# starts with the previous release's).
ADDED = ("boxmunge-audit-rotate.service", "boxmunge-audit-rotate.timer",
         "boxmunge-autofix.service", "boxmunge-kev-watch.service", "boxmunge-kev-watch.timer",
         "boxmunge-maintenance.service", "boxmunge-maintenance.timer")
RETIRED = ("boxmunge-container-update.timer", "boxmunge-cve-scan.timer")


@pytest.mark.parametrize("mode", ["ok", "fail"])
@pytest.mark.parametrize(("old_shim", "installed"), [FLOOR_SHIM])
def test_old_shim_hop_leaves_a_working_shim(
        bundle: Path, image: str, old_shim: str, installed: str, mode: str) -> None:
    facts = _hop(bundle, image, mode, old_shim, installed)
    log = facts["log"]
    assert "Pre-flight FAILED" not in log, log
    assert "Dry-run complete. Nothing was written." in log, log
    assert facts["SHIM_IS"] == "boxmunge-upgrade", log
    # What a missing library looks like: the source loader's refusal, or a
    # function that was never defined.
    assert "unbuilt source shim" not in log and "command not found" not in log, log
    assert facts["check-probation_rc"] == "0", log
    # 0.11.11 had no jobs gate: the new shim made it, deploy's, as install does.
    assert facts["JOBS_GATE"] == "deploy:deploy:750,deploy:deploy:660", log
    # install.sh, run by the shim, leaves the previous release (the rollback
    # target) alone: nothing installed into it.
    assert facts["ENV_A_PIP_CALLS"] == "0", log
    if mode == "ok":
        assert facts["hop_rc"] == "0", log
        # Mid-hop, the old shim holds the upgrade lock; the new shim it
        # installed must not start a second upgrade or act on probation.
        assert facts["during_target_rc"] == "1", log
        assert "Another upgrade is in progress" in facts["during_target_out"], log
        assert facts["during_check-probation_rc"] == "0", log
        assert "Another upgrade is in progress; skipping" in facts["during_check-probation_out"], log
        assert facts["LIVE"] == "/opt/boxmunge/env-b" and facts["PROBATION"] == "yes", log
        # The version is recorded only by the new release's apply.
        assert facts["VERSION_BEFORE_APPLY"] == f"{installed}+abc1234", log
        assert facts["VERSION_RECORD"] == f"{NEW}+abc1234", log
        # The new shim honours the probation the old one started.
        assert facts["run_rc"] == "0" and "is on probation" in facts["run_out"], log
        assert facts["target_rc"] == "1" and "is on probation" in facts["target_out"], log
        # install.sh had the new shim write deploy's rule, through visudo:
        # nothing else in it.
        after = [line for line in facts["sudoers_after_hop"].splitlines()
                 if line and not line.startswith("#")]
        assert after == [RULE], log
        # The live units are this release's, and the new shim leaves them be.
        assert facts["UNITS"] == facts["UNITS_AFTER_INSTALL_SH"], log
        assert "restoring them" not in facts["check-probation_out"], log
    else:
        # install.sh failed: the upgrade stops before the swap.
        assert facts["hop_rc"] == "1", log
        assert facts["LIVE"] == "/opt/boxmunge/env-a" and facts["PROBATION"] == "no", log
        assert facts["VERSION_RECORD"] == f"{installed}+abc1234", log
        # Upgrades still run: this one gets as far as the (absent) download.
        assert "Failed to download bundle" in facts["run_out"], log


def test_a_failed_hop_from_the_floor_puts_the_previous_units_back(bundle: Path, image: str) -> None:
    """The apply fails after the swap: the 0.11.11 shim that started the
    upgrade rolls it back, and with it the units this release's install.sh
    put in place."""
    old_shim, installed = FLOOR_SHIM
    facts = _hop(bundle, image, "rollback", old_shim, installed)
    log = facts["log"]
    assert "apply failed (simulated)" in log and "Rollback complete" in log, log
    assert facts["hop_rc"] == "1" and facts["BLOCKLIST"] == NEW, log
    assert facts["LIVE"] == "/opt/boxmunge/env-a" and facts["PROBATION"] == "no", log
    assert facts["VERSION_RECORD"] == f"{installed}+abc1234", log
    # install.sh put this release's units in place before the swap...
    after_install = facts["UNITS_AFTER_INSTALL_SH"].split(",")
    assert set(ADDED) <= set(after_install) and not set(RETIRED) & set(after_install), log
    # ...and the rollback put back exactly the previous release's: the added
    # timers disabled and removed, the retired ones back and enabled.
    assert facts["UNITS"] == facts["UNITS_BEFORE"], log
    assert set(facts["DISABLED"].split(",")) == {u for u in ADDED if u.endswith(".timer")}, log
    assert set(RETIRED) <= set(facts["ENABLED"].split(",")), log
    # The new shim, on disk since before the swap, finds the live units are
    # the live slot's: nothing to heal.
    assert facts["SHIM_IS"] == "boxmunge-upgrade", log
    assert facts["check-probation_rc"] == "0", log
    assert "restoring them" not in facts["check-probation_out"], log
