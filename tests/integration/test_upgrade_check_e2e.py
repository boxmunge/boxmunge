"""Agent-led upgrades end to end: an agent's `upgrade-check` on a box, and the
gate that keeps `upgrade --target` off a box the check found not ready.

Each case runs upgrade_check_e2e.sh as root in a throwaway container. The box
runs this tree's built upgrade shim as release INSTALLED, with deploy's sudo
rule as that shim writes it and the host's Docker daemon through its socket.
Release NEXT is this tree's real bundle (`make bundle`), with upgrade notes
compiled by this tree's compiler that mark NEXT breaking. deploy runs this
tree's `upgrade-check --version NEXT --json`, which sudoes the shim's
`check`: the shim fetches and verifies NEXT, runs its prerequisite scripts,
builds its venv, and runs its readiness command and its upgrade's dry run as
deploy, each through systemd-run. The network, cosign, systemd-run and pip
are stand-ins (see the script), so the venv runs NEXT's code on packages
installed beforehand; the readiness command, the dry run, sudo, visudo and
Docker are real. The sandbox systemd-run puts around each run is not here: it
is checked on a real Debian 13 box before a release is tagged.
"""
from __future__ import annotations

import json
import re
import subprocess
import tarfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

import pytest

from tests.integration.conftest import skip_no_docker

pytestmark = [pytest.mark.integration, skip_no_docker]

REPO = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
BASE = "python:3.13-slim"
INSTALLED = "0.11.8"  # the release this tree becomes
NEXT = "0.12.0"       # a breaking release after it: this tree, numbered so
PREREQUISITES = ("bootstrap/upgrade-floor.sh", "bootstrap/python-floor.sh",
                  "bootstrap/compose-version.sh")
# The box's Docker CLI and Compose come from Docker's apt repository, as
# bootstrap/init-host.sh installs them; sudo brings visudo.
PREPARE = f"""set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends ca-certificates sudo >/dev/null
install -m 0755 -d /etc/apt/keyrings
python3 -c 'import urllib.request; urllib.request.urlretrieve("https://download.docker.com/linux/debian/gpg", "/etc/apt/keyrings/docker.asc")'
echo "deb [signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends docker-ce-cli docker-compose-plugin >/dev/null
cp -R /bundle/boxmunge /relsrc
sed -i 's/^version = ".*"$/version = "{NEXT}"/' /relsrc/pyproject.toml
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
    """BASE plus Docker's CLI and Compose, sudo, and /relvenv: this tree's
    bundle, pip-installed as release NEXT."""
    tag = f"bmtest-check-e2e-{uuid.uuid4().hex[:10]}:prepared"
    builder = f"bmtest-check-e2e-prep-{uuid.uuid4().hex[:10]}"
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


@dataclass
class Run:
    facts: dict[str, str]
    rc: dict[str, int]
    files: dict[str, str]
    log: str

    @property
    def check(self) -> dict[str, Any]:
        """What `upgrade-check --json` printed: the deploy side's reading of
        the shim's verdict (stage "shim" if it could not read one)."""
        return json.loads(self.files["check.json"])


def _e2e(bundle: Path, image: str, case: str) -> Run:
    runner = f"bmtest-check-e2e-{uuid.uuid4().hex[:10]}"
    try:
        result = _docker("run", "--rm", "--name", runner,
                         "-v", f"{bundle}:/bundle:ro", "-v", f"{HERE}:/t:ro",
                         "-v", f"{REPO / 'tests'}:/src/tests:ro",
                         "-v", "/var/run/docker.sock:/var/run/docker.sock", image,
                         "bash", "/t/upgrade_check_e2e.sh", case, INSTALLED, BASE)
    finally:
        _docker("rm", "-f", runner)
    log = result.stdout + result.stderr
    assert result.returncode == 0 and result.stdout.endswith("--- end\n"), log
    return Run(facts=dict(re.findall(r"^([A-Z_]+)=(\S+)$", result.stdout, re.M)),
               rc={step.lower(): int(rc) for step, rc in
                   re.findall(r"^(CHECK|TARGET) rc=(\d+)$", result.stdout, re.M)},
               files=dict(re.findall(r"^--- (\S+)\n(.*?)(?=^--- )", result.stdout, re.M | re.S)),
               log=log)


def _box_unchanged(run: Run) -> None:
    """What a check or a refused upgrade leaves: the box as it was."""
    assert run.facts["BLOCKLIST_UNCHANGED"] == "yes", run.log
    assert run.facts["SHIM_UNCHANGED"] == "yes", run.log
    assert run.facts["LIVE"] == "/opt/boxmunge/env-a", run.log
    assert run.facts["VERSION_RECORD"] == f"{INSTALLED}+abc1234", run.log
    assert run.facts["STANDBY"] == "no" and run.facts["CHECK_DIR"] == "no", run.log


def _prerequisite_units() -> list[str]:
    """The systemd-run units of NEXT's prerequisite scripts, and who ran them."""
    return [f"boxmunge-check-prereq-{Path(p).stem} root" for p in PREREQUISITES]


def _findings(check: dict[str, Any]) -> dict[str, list[tuple[str, str, str]]]:
    """{project: [(rule id, severity, message)]} of the readiness answer."""
    return {p["name"]: [(f["id"], f["severity"], f["message"]) for f in p["findings"]]
            for p in check["readiness"]["projects"]}


def test_e2e_raised_python_floor_is_blocked_box_level_no_venv(bundle: Path, image: str) -> None:
    run = _e2e(bundle, image, "floor99")
    check, log = run.check, run.log
    assert run.rc["check"] == 1, log
    assert (check["result"], check["stage"]) == ("blocked", "prerequisites"), log
    assert (check["target"], check["installed"]) == (NEXT, INSTALLED), log
    met = {p["script"]: p for p in check["prerequisites"]}
    assert tuple(met) == PREREQUISITES, log
    floor = met["bootstrap/python-floor.sh"]
    assert not floor["ok"] and "boxmunge needs Python 99.0 or newer" in floor["message"], log
    assert met["bootstrap/upgrade-floor.sh"]["ok"] and met["bootstrap/compose-version.sh"]["ok"], log
    assert any("python-floor.sh" in reason for reason in check["reasons"]), log
    # A box-level verdict: no venv was built, nothing of NEXT ran as deploy.
    assert check["readiness"] is None and check["dry_run"] is None, log
    assert "check-pip.log" not in run.files, log
    assert run.files["check-units.log"].splitlines() == _prerequisite_units(), log
    _box_unchanged(run)


def test_e2e_new_project_refusal_lists_projects_and_target_refuses_without_blocklisting(
        bundle: Path, image: str) -> None:
    run = _e2e(bundle, image, "blocked")
    check, log = run.check, run.log
    assert run.rc["check"] == 1, log
    assert check["result"] == "blocked" and check["stage"] in ("complete", "dry_run"), log
    assert all(p["ok"] for p in check["prerequisites"]), log
    readiness = check["readiness"]
    assert (readiness["release"], readiness["installed"]) == (NEXT, INSTALLED), log
    assert readiness["box"] == [], log
    # Every deployed project is listed, each with what NEXT asks of it.
    found = _findings(check)
    assert sorted(found) == ["blog", "shop"], log
    [(rule, severity, message)] = [f for f in found["blog"] if f[0] == "project.image_missing"]
    assert severity == "block" and "is not on this box" in message, log
    [(rule, severity, message)] = [f for f in found["shop"] if f[0] == "project.validate"]
    assert severity == "todo" and "pull_policy: always" in message, log
    assert "project.image_missing" not in [f[0] for f in found["shop"]], log  # BASE is here
    # NEXT's own scripts and its venv build ran as root; its readiness
    # command and its upgrade's dry run as deploy.
    assert run.files["check-units.log"].splitlines() == _prerequisite_units() + [
        "boxmunge-check-venv root", "boxmunge-check-readiness deploy",
        "boxmunge-check-dryrun deploy"], log

    # The upgrade an agent would try next crosses NEXT, a breaking release:
    # NEXT's readiness check runs first and refuses it, unblocklisted.
    target = run.files["target.log"]
    assert run.rc["target"] == 1, log
    assert f"crosses the breaking release {NEXT}" in target, log
    assert f"Not upgrading to {NEXT}: its readiness check found what blocks it" in target, log
    assert "is not on this box" in target, log
    assert f"{NEXT} is not blocklisted" in target, log
    assert f"upgrade-check --version {NEXT}" in target, log
    assert f"sudo /opt/boxmunge/bin/boxmunge-upgrade force-target {NEXT}" in target, log
    assert run.files["target-units.log"].splitlines() == _prerequisite_units() + [
        "boxmunge-check-readiness deploy"], log
    assert run.files["alerts.log"].splitlines() == [f"0 boxmunge upgrade to {NEXT} refused"], log
    assert "upgrade refused: box not ready" in run.files["oplog.log"], log
    _box_unchanged(run)


def test_e2e_target_without_readiness_is_cant_verify(bundle: Path, image: str) -> None:
    run = _e2e(bundle, image, "noready")
    check, log = run.check, run.log
    assert run.rc["check"] == 1, log
    assert (check["result"], check["stage"]) == ("cant_verify", "readiness"), log
    [reason] = check["reasons"]
    assert f"{NEXT} has no working readiness command" in reason, log
    assert "unknown command 'upgrade-readiness'" in reason, log
    # Never a verdict from another release's rules, and no dry run after it.
    assert check["readiness"] is None and check["dry_run"] is None, log
    assert run.files["check-units.log"].splitlines()[-1] == "boxmunge-check-readiness deploy", log
    _box_unchanged(run)
