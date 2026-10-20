#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Debian 13 VM runs of a boxmunge 0.10.1 box upgrading to the beta around a
stage (spec 'VM harness (Debian 13)').

Each scenario boots a fresh VM with vm-test.py's helpers, installs the
v0.10.1 release tarball with `boxmunge server-setup --local-bundle`, deploys
v1 of a small busybox project, then runs its steps in order over ssh: each is
(description, user, command, expected exit code[, text a refusal must print]).
`deploy` steps go through the deploy shell; `root` steps run with sudo as
supervisor (operator-only commands such as legacy-stage run as root via
boxmunge-server).

The beta is this tree's `make bundle`, relabelled as release BETA_VERSION
and reached by 0.10.1's own upgrade shim (`boxmunge-upgrade target`): on the
VM, curl serves that release's URLs from /root/vm-release and cosign accepts
exactly its SHA256SUMS, because a local build is not signed. Everything else
the shim does (sha256sum -c, pip with hashes, dry-run, stash, swap,
install.sh, apply, probation) is real.

Usage:
    ./tests/vm/vm-staging.py <scenario>   # discard | keep-then-rollback |
                                          # hotfix-during-stage | probation-rollback
    ./tests/vm/vm-staging.py teardown     # kill a VM left from a failed run

Manual, like vm-test.py: not run in CI. On failure the VM is left running.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path

_spec = importlib.util.spec_from_file_location("vm_test", Path(__file__).with_name("vm-test.py"))
vm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vm)

OLD_VERSION = "0.10.1"
OLD_RELEASE = f"https://github.com/boxmunge/boxmunge/releases/download/v{OLD_VERSION}"
BETA_VERSION = "0.10.99"   # this tree's build, labelled for the shim
WORK = vm.CACHE_DIR / "vm-staging"
SSH_TIMEOUT = 1500          # an upgrade re-runs install.sh: longer than ssh_run's 300 s
PORT = vm.PORTS["ssh_boxmunge"]
REFS = {"v1": "2026-10-16T09", "v2": "2026-10-16T10", "v1_hotfix": "2026-10-16T11"}
LABELS = {"v1": "v1", "v2": "v2", "v1_hotfix": "v1-hotfix"}
HOURS = {"v1": "09", "v2": "10", "v1_hotfix": "11"}
SHIM = "/opt/boxmunge/bin/boxmunge-upgrade"
IDS = {"vmstage": "01VMSTAGE00000000000000001", "vmstage2": "01VMSTAGE00000000000000002",
       "vmgit": "01VMSTAGE00000000000000003"}
UPLOADED = '"$(getent passwd supervisor | cut -d: -f6)/vm-staging"'

# Probation is ended or failed the way tests/shim does it: through its state
# file, or with a health check that reports critical (check-probation has no
# force flags). The wrapper is left behind in the abandoned slot.
END_PROBATION = (
    "python3 -c \"import json; f='/opt/boxmunge/upgrade-state/probation.json'; "
    "d=json.load(open(f)); d['expires_at']='2000-01-01T00:00:00+00:00'; "
    f"json.dump(d, open(f, 'w'))\" && {SHIM} check-probation")
FAIL_PROBATION = (
    's=$(readlink -f /opt/boxmunge/env-active)/bin/boxmunge-server && mv "$s" "$s.real" && '
    "{ echo '#!/bin/sh'; echo '[ \"$1\" = health ] && exit 2'; "
    "echo \"exec $s.real \\\"\\$@\\\"\"; } > \"$s\" && chmod +x \"$s\" && "
    f"{SHIM} check-probation")
UPGRADE = f"{SHIM} target {BETA_VERSION}"
LIVE_IS_OLD = f"/opt/boxmunge/env-active/bin/boxmunge-server --version | grep -qx 'boxmunge {OLD_VERSION}'"


def runs(project: str, label: str) -> str:
    return f'test "$(vm-version {project})" = {label}'


def no_staging(project: str) -> str:
    return f'test -z "$(docker ps -aq --filter label=com.docker.compose.project={project}-staging)"'


def stage_and_recreate(project: str) -> list[tuple[str, str, str, int]]:
    """A 0.10.1 stage whose production was started from the staged files, the
    way 0.10.1's resume does it (from the project dir)."""
    return [(f"0.10.1 stages {project} v2", "deploy", f"stage {project} --ref {{v2}}", 0),
            (f"0.10.1 pauses {project}", "deploy", f"pause {project} --yes", 0),
            (f"0.10.1 resumes {project} from the staged files", "deploy",
             f"resume {project} --yes", 0)]


SCENARIOS: dict[str, dict] = {
    "discard": {"projects": ["vmstage"], "steps": [
        ("0.10.1 stages v2", "deploy", "stage vmstage --ref {v2}", 0),
        ("upgrade to the beta", "root", UPGRADE, 0),
        ("the stage was left as is", "root",
         f"{runs('vmstage', 'v1')} && {runs('vmstage-staging', 'v2')}", 0),
        ("and recorded for its alert", "root",
         "grep -q '\"vmstage\"' /opt/boxmunge/state/legacy-stages.json", 0),
        ("legacy-stage refused during probation", "root",
         "boxmunge-server legacy-stage vmstage --discard", 1, "is on probation until"),
        ("end probation", "root", END_PROBATION, 0),
        ("legacy-stage --discard", "root", "boxmunge-server legacy-stage vmstage --discard", 0),
        ("production runs v1, staging is gone", "root",
         f"{runs('vmstage', 'v1')} && {no_staging('vmstage')}", 0),
        ("a deploy works again", "deploy", "prod-deploy vmstage --ref {v1_hotfix}", 0),
        ("production runs the hotfix", "root", runs("vmstage", "v1-hotfix"), 0),
    ]},
    "keep-then-rollback": {"projects": ["vmstage", "vmstage2"], "steps": [
        *stage_and_recreate("vmstage"),
        *stage_and_recreate("vmstage2"),
        ("both run the staged v2", "root",
         f"{runs('vmstage', 'v2')} && {runs('vmstage2', 'v2')}", 0),
        ("upgrade to the beta", "root", UPGRADE, 0),
        ("end probation", "root", END_PROBATION, 0),
        ("legacy-stage --keep-staged", "root",
         "boxmunge-server legacy-stage vmstage --keep-staged", 0),
        ("rollback", "deploy", "rollback vmstage --yes", 0),
        ("production runs v1", "root", f"{runs('vmstage', 'v1')} && {no_staging('vmstage')}", 0),
        ("--discard of a recreated stage needs confirming", "root",
         "boxmunge-server legacy-stage vmstage2 --discard", 1,
         "rerun with --discard --confirm-recreated"),
        ("legacy-stage --discard --confirm-recreated", "root",
         "boxmunge-server legacy-stage vmstage2 --discard --confirm-recreated", 0),
        ("the second runs v1", "root",
         f"{runs('vmstage2', 'v1')} && {no_staging('vmstage2')}", 0),
    ]},
    "hotfix-during-stage": {"projects": ["vmstage"], "steps": [
        ("upgrade to the beta first", "root", UPGRADE, 0),
        ("stage v2", "deploy", "stage vmstage --ref {v2}", 0),
        ("staging runs v2 beside production's v1", "root",
         f"{runs('vmstage', 'v1')} && {runs('vmstage-staging', 'v2')}", 0),
        ("prod-deploy a hotfix during the stage", "deploy",
         "prod-deploy vmstage --ref {v1_hotfix}", 0),
        ("production runs the hotfix", "root", runs("vmstage", "v1-hotfix"), 0),
        ("promote", "deploy", "promote vmstage", 0),
        ("production runs v2", "root", f"{runs('vmstage', 'v2')} && {no_staging('vmstage')}", 0),
        ("rollback", "deploy", "rollback vmstage --yes", 0),
        ("rollback returned to the hotfix", "root", runs("vmstage", "v1-hotfix"), 0),
    ]},
    "probation-rollback": {"projects": ["vmstage"], "git": True, "steps": [
        ("upgrade to the beta", "root", UPGRADE, 0),
        ("stage v2 on the beta", "deploy", "stage vmstage --ref {v2}", 0),
        ("force the probation to fail", "root", FAIL_PROBATION, 0),
        ("0.10.1 is live again and staging was torn down", "root",
         f"{LIVE_IS_OLD} && {no_staging('vmstage')} && {runs('vmstage', 'v1')}", 0),
        ("put the bundles back in the inbox", "root", "vm-restock", 0),
        ("0.10.1 stages again", "deploy", "stage vmstage --ref {v2}", 0),
        ("0.10.1 unstages", "deploy", "unstage vmstage", 0),
        ("0.10.1 deploys a bundle project", "deploy", "prod-deploy vmstage --ref {v1_hotfix}", 0),
        ("0.10.1 deploys the git project", "deploy", "prod-deploy vmgit", 0),
        ("both run what was deployed", "root",
         f"{runs('vmstage', 'v1-hotfix')} && {runs('vmgit', 'v1')}", 0),
    ]},
}


# -- What goes on the VM -----------------------------------------------------

def _release_files(project: str, label: str, source: str = "bundle") -> dict[str, str]:
    manifest = (f"schema_version: 3\nid: {IDS[project]}\nproject: {project}\n"
                f"source: {source}\nhosts: [{project}.example.com]\n"
                "services: {app: {internal: true}}\nbackup: {type: none}\n")
    if source == "git":
        manifest += f"repo: /srv/{project}.git\nref: main\n"
    compose = ("services:\n  app:\n    image: busybox:1.36\n"
               "    command: [\"sh\", \"-c\", \"trap 'exit 0' TERM; while :; do sleep 1; done\"]\n"
               f"    network_mode: none\n    environment: {{VERSION: {label}}}\n")
    return {"manifest.yml": manifest, "compose.yml": compose}


def _add(tar: tarfile.TarFile, name: str, text: str, mode: int = 0o644) -> None:
    data = text.encode()
    info = tarfile.TarInfo(name)
    info.size, info.mode, info.mtime = len(data), mode, int(time.time())
    tar.addfile(info, io.BytesIO(data))


def write_bundles(out: Path, projects: list[str]) -> None:
    """Inbox bundles named the way reception names them, one per release label."""
    for project in projects:
        for key, label in LABELS.items():
            name = out / f"{project}-2026-10-16T{HOURS[key]}0000000000.tar.gz"
            with tarfile.open(name, "w:gz") as tar:
                for fname, text in _release_files(project, label).items():
                    _add(tar, f"{project}/{fname}", text)


def build_beta_release(out: Path) -> None:
    """This tree's bundle as release BETA_VERSION, with its SHA256SUMS."""
    bundle = vm.build_server_bundle()
    with tempfile.TemporaryDirectory() as tmp:
        with tarfile.open(bundle) as tar:
            tar.extractall(tmp, filter="tar")
        pyproject = Path(tmp) / "boxmunge" / "pyproject.toml"
        text = pyproject.read_text()
        current = f'version = "{OLD_VERSION}"'
        if current not in text:
            raise RuntimeError(f"{pyproject} has no {current!r} line to relabel; update "
                               f"BETA_VERSION handling in {Path(__file__).name}")
        pyproject.write_text(text.replace(current, f'version = "{BETA_VERSION}"', 1))
        tarball = out / f"boxmunge-{BETA_VERSION}.tar.gz"
        with tarfile.open(tarball, "w:gz") as tar:
            tar.add(Path(tmp) / "boxmunge", arcname="boxmunge")
    digest = hashlib.sha256(tarball.read_bytes()).hexdigest()
    (out / "SHA256SUMS").write_text(f"{digest}  {tarball.name}\n")
    for empty in ("SHA256SUMS.sig", "SHA256SUMS.cert"):
        (out / empty).write_text("")


def fetch_old_release(out: Path) -> Path:
    """The v0.10.1 release tarball, checked against the release's SHA256SUMS."""
    name = f"boxmunge-{OLD_VERSION}.tar.gz"
    tarball, sums = out / name, out / f"SHA256SUMS-{OLD_VERSION}"
    for url, path in ((f"{OLD_RELEASE}/{name}", tarball), (f"{OLD_RELEASE}/SHA256SUMS", sums)):
        if not path.exists():
            with urllib.request.urlopen(url, timeout=60) as response:
                path.write_bytes(response.read())
    digest = hashlib.sha256(tarball.read_bytes()).hexdigest()
    if f"{digest}  {name}" not in sums.read_text().splitlines():
        raise RuntimeError(f"{tarball} does not match {OLD_RELEASE}/SHA256SUMS; delete both "
                           f"and rerun")
    return tarball


HELPERS = {
    # The running container's VERSION, for a compose project.
    "vm-version": """#!/bin/sh
id=$(docker ps -q --filter "label=com.docker.compose.project=$1" | head -1)
[ -n "$id" ] && docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$id" \\
    | sed -n 's/^VERSION=//p'
""",
    # Put every test bundle back in the inbox (deploys consume them).
    "vm-restock": """#!/bin/sh
set -e
for f in /root/vm-bundles/*.tar.gz; do
    [ -e "/opt/boxmunge/inbox/${f##*/}" ] || install -o deploy -g deploy -m 0640 "$f" /opt/boxmunge/inbox/
done
""",
    # The beta release's URLs come from /root/vm-release; all others go out.
    "curl": f"""#!/bin/sh
for a; do last=$a; done
case "$last" in
https://github.com/boxmunge/boxmunge/releases/download/v{BETA_VERSION}/*)
    prev=""; for a; do [ "$prev" = -o ] && out=$a; prev=$a; done
    exec cp "/root/vm-release/${{last##*/}}" "$out" ;;
esac
exec /usr/bin/curl "$@"
""",
    # The local build is unsigned: accept exactly its SHA256SUMS.
    "cosign": """#!/bin/sh
if [ "$1" = verify-blob ]; then
    for a; do last=$a; done
    cmp -s "$last" /root/vm-release/SHA256SUMS && exit 0
fi
exec /usr/local/lib/vm-staging/cosign "$@"
""",
}

INSTALL_HELPERS = f"""set -e
cd {UPLOADED}
mkdir -p /usr/local/lib/vm-staging /root/vm-bundles /root/vm-release
mv /usr/local/bin/cosign /usr/local/lib/vm-staging/cosign
for h in vm-version vm-restock curl cosign; do install -m 0755 "helpers/$h" /usr/local/bin/; done
cp bundles/*.tar.gz /root/vm-bundles/ && cp release/* /root/vm-release/
vm-restock
"""

GIT_PROJECT = f"""set -e
w=$(mktemp -d) && cd "$w" && git init -q -b main
cp {UPLOADED}/git/* .
git add -A && git -c user.name=t -c user.email=t@example.com commit -qm v1
git init -q --bare -b main /srv/vmgit.git && git push -q /srv/vmgit.git HEAD:main
chown -R deploy:deploy /srv/vmgit.git
"""


# -- Running -----------------------------------------------------------------

def ssh(user: str, command: str) -> subprocess.CompletedProcess:
    """A step's command: through the deploy shell, or as root via supervisor."""
    login, remote = (("deploy", command) if user == "deploy" else
                     ("supervisor", f"sudo bash -c {shlex.quote(command)}"))
    return subprocess.run(["ssh", *vm.SSH_OPTS, "-p", str(PORT), f"{login}@localhost", remote],
                          capture_output=True, text=True, check=False, timeout=SSH_TIMEOUT)


def run_steps(steps: list[tuple]) -> None:
    """Each step's exit code, and for a refusal that says why, its reason."""
    for description, user, command, expect, *why in steps:
        for key, ref in REFS.items():   # not str.format: shell braces stay as they are
            command = command.replace(f"{{{key}}}", ref)
        result = ssh(user, command)
        if result.returncode != expect:
            vm.step_fail(description, f"{user}: {command} exited {result.returncode}, expected "
                         f"{expect}\nstdout: {result.stdout[-3000:]}\nstderr: {result.stderr[-3000:]}")
        if why and why[0] not in result.stdout + result.stderr:
            vm.step_fail(description, f"{user}: {command} did not say {why[0]!r}\nstdout: "
                         f"{result.stdout[-3000:]}\nstderr: {result.stderr[-3000:]}")
        vm.step_pass(description)


def trust_host_key() -> None:
    """Record the VM's host key, read over the test user's authenticated ssh
    (the VM's own key file is the out-of-band source), for both ports
    server-setup uses, so it never needs ssh-keyscan: Debian 13's sshd
    penalises those unauthenticated scans. cleanup_vm removes the entries."""
    key = vm.ssh_run("test", vm.PORTS["ssh_initial"],
                     "cat /etc/ssh/ssh_host_ed25519_key.pub").stdout.split()[:2]
    with open(Path.home() / ".ssh" / "known_hosts", "a") as known:
        for port in (vm.PORTS["ssh_initial"], PORT):
            known.write(f"[localhost]:{port} {' '.join(key)}\n")


def preinstall_gnupg_for_old_release() -> None:
    """0.10.1's installer needs gpg before it installs it; boxes installed
    when cloud images shipped gnupg have it. Only this legacy base install
    needs it: the shared cloud-init user-data stays without gnupg so the
    beta's fresh install (vm-test.py) exercises the real installer path."""
    result = vm.ssh_run("test", vm.PORTS["ssh_initial"],
                        "sudo apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive "
                        "apt-get install -y gnupg", check=False)
    if result.returncode != 0:
        vm.step_fail("pre-install gnupg for the 0.10.1 base",
                     f"stdout: {result.stdout[-3000:]}\nstderr: {result.stderr[-3000:]}")
    vm.step_pass(f"gnupg on the guest, as a {OLD_VERSION}-era box has it")


def install_old_release(hostname: str, tarball: Path) -> None:
    vm.phase(f"Install boxmunge {OLD_VERSION}")
    preinstall_gnupg_for_old_release()
    trust_host_key()
    cmd = ["boxmunge", "server-setup", "test@localhost", "-p", str(vm.PORTS["ssh_initial"]),
           "--email", "test@example.com", "--self-signed-tls", "--yes", "--hostname", hostname,
           "--boxmunge-ssh-port", "922", "--no-aide", "--no-crowdsec", "--no-auto-updates",
           "--local-bundle", str(tarball)]
    log = WORK / "server-setup.log"
    with open(log, "w") as out:
        rc = subprocess.run(cmd, stdout=out, stderr=subprocess.STDOUT, check=False).returncode
    if rc != 0:
        vm.step_fail("server-setup exited non-zero", log.read_text()[-3000:])
    vm.step_pass(f"server-setup installed {tarball.name}")
    run_steps([("0.10.1 is live", "root", LIVE_IS_OLD, 0)])


def upload(local: Path) -> None:
    scp = ["scp", "-O", "-r", *vm.SSH_OPTS, "-P", str(PORT), str(local), "supervisor@localhost:"]
    result = subprocess.run(scp, capture_output=True, text=True, check=False, timeout=300)
    if result.returncode != 0:
        vm.step_fail(f"upload {local.name}", result.stderr)


def prepare_box(scenario: dict, stage_dir: Path) -> None:
    vm.phase("Prepare the box")
    for name, text in HELPERS.items():
        path = stage_dir / "helpers" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    (stage_dir / "bundles").mkdir()
    write_bundles(stage_dir / "bundles", scenario["projects"])
    shutil.copytree(WORK / "release", stage_dir / "release")
    steps = [("install the helpers, the bundles and the beta release", "root",
              INSTALL_HELPERS, 0)]
    for project in scenario["projects"]:
        steps += [(f"register {project}", "deploy", f"project-add {project}", 0),
                  (f"0.10.1 deploys {project} v1", "deploy",
                   f"prod-deploy {project} --ref {{v1}}", 0),
                  (f"{project} runs v1", "root", runs(project, "v1"), 0)]
    if scenario.get("git"):
        (stage_dir / "git").mkdir()
        for fname, text in _release_files("vmgit", "v1", "git").items():
            (stage_dir / "git" / fname).write_text(text)
        steps += [("a git origin on the box", "root", GIT_PROJECT, 0),
                  ("register vmgit", "deploy", "project-add vmgit", 0),
                  ("0.10.1 adds the git project", "deploy",
                   "add-git-project vmgit /srv/vmgit.git", 0),
                  ("0.10.1 deploys it", "deploy", "prod-deploy vmgit", 0)]
    upload(stage_dir)
    run_steps(steps)


def boot() -> None:
    vm.phase("Boot a Debian 13 VM")
    vm.clean_known_hosts()
    vm.ensure_cache_dir()
    vm.download_image()
    vm.build_cloud_init_iso(vm.detect_ssh_pubkey())
    vm.create_overlay_disk()
    vm.launch_qemu()
    vm.wait_for_ssh(vm.PORTS["ssh_initial"])  # raises with ssh's last error
    vm.verify_target_is_debian(vm.PORTS["ssh_initial"])
    vm.step_pass("VM booted and verified as Debian")


def run_scenario(name: str) -> int:
    scenario = SCENARIOS[name]
    start = time.time()
    WORK.mkdir(parents=True, exist_ok=True)
    try:
        vm.phase(f"Releases: {OLD_VERSION} and the beta as {BETA_VERSION}")
        old = fetch_old_release(WORK)
        shutil.rmtree(WORK / "release", ignore_errors=True)
        (WORK / "release").mkdir()
        build_beta_release(WORK / "release")
        vm.step_pass(f"{old.name}; boxmunge-{BETA_VERSION}.tar.gz built from this tree")
        boot()
        install_old_release("boxmunge-staging-test", old)
        with tempfile.TemporaryDirectory() as tmp:
            stage_dir = Path(tmp) / "vm-staging"
            stage_dir.mkdir()
            prepare_box(scenario, stage_dir)
        vm.phase(f"Scenario: {name}")
        run_steps(scenario["steps"])
    except vm.TestFailure as e:
        print(f"\n  SCENARIO {name} FAILED ({time.time() - start:.0f}s): {e}")
        print(f"  VM left running: ssh {' '.join(vm.SSH_OPTS)} -p {PORT} supervisor@localhost")
        print(f"  Tear down with: {sys.argv[0]} teardown")
        return 1
    except Exception as e:  # noqa: BLE001 - infrastructure, not the scenario
        print(f"\nINFRASTRUCTURE ERROR: {e}", file=sys.stderr)
        vm.cleanup_vm()
        return 2
    print(f"\n  SCENARIO {name} PASSED ({time.time() - start:.0f}s)")
    vm.cleanup_vm()
    return 0


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in (*SCENARIOS, "teardown"):
        print(f"Usage: {sys.argv[0]} {{{'|'.join(SCENARIOS)}|teardown}}", file=sys.stderr)
        sys.exit(2)
    if sys.argv[1] == "teardown":
        vm.cmd_teardown()
        sys.exit(0)
    sys.exit(run_scenario(sys.argv[1]))


if __name__ == "__main__":
    main()
