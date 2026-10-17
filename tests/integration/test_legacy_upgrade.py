# SPDX-License-Identifier: Apache-2.0
"""A real 0.10.1 stage survives the beta's upgrade untouched, a rollback to
0.10.1 then finds its own state, and the beta's legacy-stage resolves it
(spec 'Test plan', 'Migration from 0.10.1').

Each case runs legacy_upgrade.sh as root in a throwaway container with the
host's Docker socket: boxmunge 0.10.1 (`git archive v0.10.1`) and the beta
(this tree's `make bundle`) are installed once into a prepared image, the
way test_shim_hop.py uses the built bundle.
"""
from __future__ import annotations

import re
import subprocess
import tarfile
import uuid
from pathlib import Path
from typing import Iterator

import pytest

from tests.integration.conftest import skip_no_docker
from tests.integration.docker_images import ensure_busybox

pytestmark = [pytest.mark.integration, skip_no_docker]

REPO = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
BASE = "python:3.13-slim"
# Docker's own packages: Debian's docker-compose is older than the beta's
# minimum Compose (compose_version.MIN_COMPOSE_VERSION).
PREPARE = """set -e
apt-get -qq update >/dev/null
apt-get -qq install -y --no-install-recommends ca-certificates curl git >/dev/null
install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
echo "deb [signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
$(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
apt-get -qq update >/dev/null
apt-get -qq install -y --no-install-recommends docker-ce-cli docker-compose-plugin >/dev/null
useradd --system --no-create-home deploy
cp -R /v0101 /src-0101 && cp -R /bundle/boxmunge /src-beta
python3 -m venv /venv-0101 && /venv-0101/bin/pip -q install /src-0101
python3 -m venv /venv-beta && /venv-beta/bin/pip -q install /src-beta
"""


def _docker(*args: str, timeout: int = 600) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True,
                          timeout=timeout, check=False)


def _v0101_archive() -> bytes:
    """0.10.1's source. CI's checkout is shallow, without tags: its
    integration job fetches this one tag in the step "Fetch the v0.10.1 tag"."""
    tag = subprocess.run(["git", "-C", str(REPO), "rev-parse", "-q", "--verify",
                          "refs/tags/v0.10.1^{commit}"], capture_output=True, check=False)
    if tag.returncode != 0:
        pytest.fail("tag v0.10.1 is not in this checkout: fetch it with `git fetch --no-tags "
                    "--depth=1 origin refs/tags/v0.10.1:refs/tags/v0.10.1` (CI: the "
                    "integration job's step \"Fetch the v0.10.1 tag\")")
    return subprocess.run(["git", "-C", str(REPO), "archive", "v0.10.1"], check=True,
                          capture_output=True).stdout


@pytest.fixture(scope="module")
def image(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    out = tmp_path_factory.mktemp("legacy")
    v0101 = out / "v0101"
    v0101.mkdir()
    archive = _v0101_archive()
    subprocess.run(["tar", "-x", "-C", str(v0101)], input=archive, check=True)
    tarball = out / "boxmunge.tar.gz"
    subprocess.run(["make", "-C", str(REPO), "bundle", f"BUNDLE={tarball}"],
                   check=True, capture_output=True, text=True)
    with tarfile.open(tarball) as tar:
        tar.extractall(out / "bundle", filter="tar")
    ensure_busybox()
    tag = f"bmtest-legacy-{uuid.uuid4().hex[:10]}:prepared"
    builder = f"bmtest-legacy-prep-{uuid.uuid4().hex[:10]}"
    try:
        made = _docker("run", "--name", builder, "-v", f"{v0101}:/v0101:ro",
                       "-v", f"{out / 'bundle'}:/bundle:ro", BASE, "bash", "-c", PREPARE,
                       timeout=1800)
        assert made.returncode == 0, made.stdout + made.stderr
        committed = _docker("commit", builder, tag)
        assert committed.returncode == 0, committed.stderr
    finally:
        _docker("rm", "-f", builder)
    yield tag
    _docker("image", "rm", "-f", tag)


def _run(image: str, kind: str, way: str) -> dict[str, str]:
    project = f"legacyt{uuid.uuid4().hex[:8]}"
    runner = f"bmtest-legacy-{uuid.uuid4().hex[:10]}"
    try:
        result = _docker("run", "--rm", "--name", runner,
                         "-v", "/var/run/docker.sock:/var/run/docker.sock",
                         "-v", f"{HERE}:/t:ro", image,
                         "bash", "/t/legacy_upgrade.sh", kind, way, project, timeout=900)
    finally:
        # A timeout kills only the docker client: the script's container runs
        # on. Stop it first, so it cannot start more containers after the sweep.
        _docker("rm", "-f", runner)
        # The script removes them itself; this covers a script that died.
        for p in (project, f"{project}-staging"):
            ids = _docker("ps", "-aq", "--filter", f"label=com.docker.compose.project={p}")
            if ids.stdout.split():
                _docker("rm", "-f", *ids.stdout.split())
    assert result.returncode == 0, result.stdout + result.stderr
    facts = dict(re.findall(r"^([A-Z][A-Z0-9_]*)=(\S*)$", result.stdout, re.M))
    facts["log"] = result.stdout + result.stderr
    return facts


# The 0.10.1 setup steps legacy_upgrade.sh runs for each kind: every one must
# have run and passed.
SETUP_STEPS = {"bundle": ("ADD", "DEPLOY_V1", "STAGE", "STASH"),
               "bundle-recreated": ("ADD", "DEPLOY_V1", "STAGE", "PAUSE", "RECREATE", "STASH"),
               "leftover": ("ADD", "DEPLOY_V1", "STAGE", "PROMOTE", "STASH"),
               "git": ("REGISTER", "ADD", "DEPLOY_V1", "STAGE", "STASH")}
# What production runs once 0.10.1 has staged: the stage recreated it from
# the staged files (bundle-recreated), or promoted them (leftover).
RUNNING = {"bundle": "v1", "bundle-recreated": "v2", "leftover": "v2", "git": "v1"}
RECORDED = {"bundle": "bundle", "bundle-recreated": "bundle", "leftover": "leftover", "git": "git"}


def _left_as_is(kind: str, way: str, facts: dict[str, str]) -> None:
    log = facts["log"]
    for step in SETUP_STEPS[kind]:
        assert facts.get(f"{step}_RC") == "0", f"0.10.1 setup step {step} failed\n{log}"
    assert facts["PROD_VERSION_BEFORE"] == RUNNING[kind], log
    assert facts["CONTAINERS_BEFORE"] == ("1" if kind == "leftover" else "2"), log
    assert facts["DRY_RC"] == "0" and facts.get("DRY_LEFT") == "yes", log
    assert facts["APPLY_RC"] == ("1" if way == "failed-apply" else "0"), log
    assert facts["AFTER_FILES"] == facts["BEFORE_FILES"], log
    assert facts["AFTER_IDS"] == facts["BEFORE_IDS"], log
    assert facts["RECORD_KIND"] == RECORDED[kind], log
    assert facts.get("STASH_LINKS") == "none", log                    # D18 ran
    if kind == "git":
        assert facts.get("STASH_LINKS_BEFORE") == "yes", log         # 0.10.1's stash had links
        assert facts.get("GIT_LINK") == "yes", log                   # D19: the link survived
    for refused in ("DEPLOY_REFUSED", "PAUSE_REFUSED"):
        assert facts[f"{refused}_RC"] == "1", log
        assert facts.get(f"{refused}_WHY") == "legacy-stage", log
    assert facts["IDS_AFTER_REFUSALS"] == facts["BEFORE_IDS"], log


@pytest.mark.parametrize(("kind", "way"), [
    ("bundle", "rollback"),
    ("bundle-recreated", "rollback"),
    ("leftover", "rollback"),
    ("git", "rollback"),
    ("git", "failed-apply"),
    ("bundle", "failed-apply"),
])
def test_rollback_to_0101_finds_its_stage_as_it_was(image: str, kind: str, way: str) -> None:
    facts = _run(image, kind, way)
    log = facts["log"]
    _left_as_is(kind, way, facts)
    assert facts["RESTORE_RC"] == "0", log
    assert facts["RESTORED_FILES"] == facts["BEFORE_FILES"], log
    assert facts["REAPPLY_RC"] == "0", log
    if kind != "leftover":
        assert facts["OLD_UNSTAGE_RC"] == "0" and facts["STAGING_LEFT"] == "0", log
    # 0.10.1's own behaviour, pinned so a change is noticed: its re-apply
    # restarts production from the project dir, which holds the staged files,
    # and its unstage does not put production's release back.
    assert facts["PROD_VERSION_REAPPLIED"] == "v2", log
    if kind != "leftover":
        assert facts["PROD_VERSION_AFTER"] == "v2", log
    if kind == "git":
        # The control, run first from the same state: without the rewrite,
        # 0.10.1 refuses its own stash, on the link member.
        assert facts["UNREWRITTEN_RESTORE_RC"] == "1", log
        assert facts.get("UNREWRITTEN_RESTORE_WHY") == "link-member", log


# legacy-stage's choice per kind, and what production runs after it.
RESOLVED = {"bundle": "v1", "bundle-recreated": "v2", "leftover": "v2", "git": "v1"}


@pytest.mark.parametrize("kind", ["bundle", "bundle-recreated", "leftover", "git"])
def test_legacy_stage_resolves_a_0101_stage_after_the_upgrade(image: str, kind: str) -> None:
    facts = _run(image, kind, "resolve")
    log = facts["log"]
    _left_as_is(kind, "resolve", facts)
    if kind == "bundle-recreated":
        assert facts["DISCARD_UNCONFIRMED_RC"] == "1", log
        assert facts.get("DISCARD_UNCONFIRMED_WHY") == "confirm-recreated", log
    assert facts["RESOLVE_RC"] == "0", log
    assert facts.get("SHOW_AFTER_WHY") == "none", log
    assert facts["STAGING_LEFT"] == "0", log
    assert facts["PROD_VERSION_AFTER"] == RESOLVED[kind], log
    if kind == "bundle-recreated":       # --keep-staged: rollback returns to v1
        assert facts["ROLLBACK_RC"] == "0" and facts["PROD_VERSION_ROLLED_BACK"] == "v1", log
    assert facts["DEPLOY_AFTER_RC"] == "0" and facts["PROD_VERSION_DEPLOYED"] == "v3", log
