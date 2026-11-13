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

At or above the floor the hop completes. Older shims self-update by copying
only the bundle's scripts/boxmunge-upgrade into bin/, and install.sh can
fail, so the bundle's shim must be one self-contained file; the new shim,
once installed, must wait for the old shim's upgrade and honour the probation
it starts.

The old shims in old_shims/ are released files. Below the floor: v0.10.1;
v0.10.0 (byte for byte the shim every release from v0.9.2 to v0.10.0 shipped,
so also that of a box on v0.9.16); v0.9.1 (the shim of every release from
v0.7.0 to v0.9.1, whose import test reads `boxmunge.__version__`); and v0.6.3
(the same import test, and it never runs install.sh). Above it, each tag's
`scripts/build-shim.py` output: v0.11.0 (the floor), v0.11.5 (the last that
keeps no root record of the probation it starts), v0.11.6 (the bridge
release, the shim every box that was below the floor arrives with) and
v0.11.7 (the release before this one).

An old shim writes deploy's sudo rule as it knows it, so the verbs this
release adds to the rule (`check`, `guide`) reach a box only through
install.sh, which the old shim runs and which has the new shim write the
rule. The image has sudo, so each rule is checked by the real visudo.
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
NEW = "0.11.8"
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


@pytest.mark.parametrize("mode", ["ok", "fail"])
@pytest.mark.parametrize(("old_shim", "installed"), [
    ("boxmunge-upgrade-v0.11.0", "0.11.0"),
    ("boxmunge-upgrade-v0.11.5", "0.11.5"),
    ("boxmunge-upgrade-v0.11.6", "0.11.6"),
    ("boxmunge-upgrade-v0.11.7", "0.11.7"),
])
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
        # The new shim honours the probation the old one started (a shim
        # before 0.11.6 leaves no root record of it: it is adopted on the
        # evidence of the upgrade).
        assert facts["run_rc"] == "0" and "is on probation" in facts["run_out"], log
        assert facts["target_rc"] == "1" and "is on probation" in facts["target_out"], log
        # install.sh had the new shim write deploy's rule, through visudo.
        assert RULE in facts["sudoers_after_hop"].splitlines(), log
    else:
        # install.sh failed: the upgrade stops before the swap.
        assert facts["hop_rc"] == "1", log
        assert facts["LIVE"] == "/opt/boxmunge/env-a" and facts["PROBATION"] == "no", log
        assert facts["VERSION_RECORD"] == f"{installed}+abc1234", log
        # Upgrades still run: this one gets as far as the (absent) download.
        assert "Failed to download bundle" in facts["run_out"], log


def test_v0_11_7_hop_installs_check_and_guide_sudo_rule(bundle: Path, image: str) -> None:
    """A box on 0.11.7 is the one every box upgrades from, by its 0.11.7 shim:
    deploy may sudo `check` and `guide` (upgrade-check, upgrade-howto) once
    the hop is done, and that comes from install.sh alone."""
    facts = _hop(bundle, image, "ok", "boxmunge-upgrade-v0.11.7", "0.11.7")
    log = facts["log"]
    assert facts["hop_rc"] == "0" and facts["SHIM_IS"] == "boxmunge-upgrade", log
    # The 0.11.7 shim rewrote the rule as it knows it, early in its upgrade.
    before = [line for line in facts["sudoers_before_install_sh"].splitlines()
              if line.startswith("deploy ")]
    assert before == [f"deploy ALL=(root) NOPASSWD: {SHIM} auto, {SHIM} target *, "
                      f"{SHIM} repair-deps"], log
    # install.sh had the new shim write this release's rule: nothing else in it.
    after = [line for line in facts["sudoers_after_hop"].splitlines()
             if line and not line.startswith("#")]
    assert after == [RULE], log
    assert f"{SHIM} check *" in after[0] and f"{SHIM} guide *" in after[0], log
