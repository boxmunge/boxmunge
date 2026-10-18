#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Debian 13 VM rehearsal of the user-namespace migration (OPERATIONS.md,
"User-namespace remapping").

A box installed with boxmunge 0.10.1 (Docker 29 from Docker's repository, on
the containerd image store; or Docker 28 installed first, on the overlay2
graph driver) runs the projects of vm_userns_projects. It upgrades to this
tree's build (vm-staging.py's release plumbing), does what `userns-migrate
--check` asks (security.user lines, `data adopt`, `data chown`), migrates
while the host measures the downtime through Caddy, runs the platform's own
checks and a reboot, survives a kill -9 and a power cut in each phase,
soaks with a deploy, rolls back, migrates again and commits. The measured
figures (image MB, files shifted, downtime, bytes reclaimed) are printed as
a table row and written to .cache/vm/vm-userns/results-<flavour>.json.

A fresh beta install is remapped from its first boot: vm-test.py checks it.

Usage:
    ./tests/vm/vm-userns.py docker29     # containerd image store before
    ./tests/vm/vm-userns.py docker28     # overlay2 graph driver before
    ./tests/vm/vm-userns.py teardown

Manual, like vm-test.py: not run in CI. On failure the VM is left running.
"""
from __future__ import annotations

import importlib.util
import json
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
import vm_userns_projects as projects  # noqa: E402

_spec = importlib.util.spec_from_file_location("vm_staging", _HERE / "vm-staging.py")
st = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(st)
vm = st.vm

WORK = vm.CACHE_DIR / "vm-userns"
SHIM = st.SHIM
JOURNAL = "/opt/boxmunge/upgrade-root/userns-migration.json"
DOCKER28 = "5:28.5.2-1~debian.13~trixie"
PROBE = ("vmweb.localhost", "/")
PHASES = ("prepared", "quiesced", "switched", "rebuilt")
REMAPPED = "docker info --format '{{.SecurityOptions}}' | grep -q name=userns"
NOT_REMAPPED = f"! {{ {REMAPPED}; }}"


def deploy(project: str, version: str, expect: int = 0, why: str | None = None) -> tuple:
    step = (f"{project} {version}", "deploy",
            f"prod-deploy {project} --ref {projects.REFS[version]}", expect)
    return (*step, why) if why else step


def seeds_hold(when: str) -> list[tuple]:
    return [(f"{what} {when}", "root", f'test "$({read})" = {expect}', 0)
            for what, _, read, expect in projects.SEED]


DOCKER28_INSTALL = f"""set -e
apt-get update -qq && apt-get install -y -qq ca-certificates curl gpg
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian trixie stable" > /etc/apt/sources.list.d/docker.list
apt-get update -qq
apt-get install -y -qq docker-ce={DOCKER28} docker-ce-cli={DOCKER28} containerd.io docker-buildx-plugin docker-compose-plugin
apt-mark hold docker-ce docker-ce-cli
docker info --format '{{{{.ServerVersion}}}} {{{{.Driver}}}}' | grep -q '^28\\.5\\.2 overlay2$'
"""

BACKUP_REMOTE = """set -e
printf '[vmremote]\\ntype = local\\n' > /opt/boxmunge/config/rclone/rclone.conf
chmod 0640 /opt/boxmunge/config/rclone/rclone.conf
chgrp deploy /opt/boxmunge/config/rclone/rclone.conf
grep -q '^backup_remote:' /opt/boxmunge/config/boxmunge.yml || \
    echo 'backup_remote: "vmremote:/tmp/offsite"' >> /opt/boxmunge/config/boxmunge.yml
"""

# Ends the soak without waiting 48 hours: the journal's applied_at moved back.
END_SOAK = (f"python3 -c \"import json; f='{JOURNAL}'; d=json.load(open(f)); "
            "d['applied_at']='2000-01-01T00:00:00+00:00'; json.dump(d, open(f, 'w'))\"")

STORE_BYTES = "du -sxb /var/lib/containerd /var/lib/docker 2>/dev/null | awk '{s+=$1} END {print s}'"


def prepare(stage_dir: Path) -> None:
    vm.phase("Prepare the box")
    for name in ("vm-restock", "curl", "cosign"):
        path = stage_dir / "helpers" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(st.HELPERS[name])
    # INSTALL_HELPERS installs vm-version too; it is not used here.
    (stage_dir / "helpers" / "vm-version").write_text(st.HELPERS["vm-version"])
    projects.write_bundles(stage_dir / "bundles")
    shutil.copytree(WORK / "release", stage_dir / "release")
    st.upload(stage_dir)
    steps = [("install the helpers, the bundles and the beta release", "root",
              st.INSTALL_HELPERS, 0),
             ("a local backup remote (the migration syncs before it stops anything)", "root",
              BACKUP_REMOTE, 0)]
    for project in projects.PROJECTS:
        steps += [(f"register {project}", "deploy", f"project-add {project}", 0),
                  deploy(project, "v1")]
    steps += [(f"seed: {what}", "root", write, 0) for what, write, _, _ in projects.SEED]
    st.run_steps(steps)


def check_report(needles: list[str]) -> str:
    """`userns-migrate --check`, which must say each of `needles`."""
    result = st.ssh("root", f"{SHIM} userns-migrate --check")
    text = result.stdout + result.stderr
    if result.returncode != 0:
        vm.step_fail("userns-migrate --check", text[-3000:])
    missing = [n for n in needles if n not in text]
    if missing:
        vm.step_fail("userns-migrate --check", f"did not say {missing}:\n{text[-4000:]}")
    vm.step_pass(f"userns-migrate --check says {needles}")
    return text


def declare_and_adopt() -> None:
    vm.phase("Do what --check asks")
    check_report(["VERDICT: not ready", "vmdb/maria (mariadb:11) runs as its image's root",
                  "vmweb/web (nginx:1.27-alpine) runs as its image's root",
                  "boxmunge data adopt vmanon db:/var/lib/postgresql/data <name>"])
    st.run_steps([
        deploy("vmdb", "v2"), deploy("vmweb", "v2"),
        deploy("vmanon", "v2", 1, "boxmunge data adopt vmanon db:/var/lib/postgresql/data pgdata"),
        ("abandon the refused install", "deploy", "prod-deploy vmanon --abandon", 0),
        ("data adopt", "deploy", "data adopt vmanon db:/var/lib/postgresql/data pgdata", 0),
        ("restock the inbox", "root", "vm-restock", 0),
        deploy("vmanon", "v2"),
        deploy("vmapp", "v2", 1, "boxmunge data chown vmapp web 10001:10001"),
        ("data chown", "deploy", "data chown vmapp web 10001:10001", 0),
        ("restock the inbox", "root", "vm-restock", 0),
        deploy("vmapp", "v2"),
        ("a suppression to carry", "root",
         "boxmunge-server security suppress CVE-2024-45337 --project vmweb --until 2099-01-01 "
         "--reason 'userns rehearsal'", 0),
        *seeds_hold("after the declarations"),
    ])


class Downtime:
    """Polls a site through Caddy once a second; the window is the first to
    the last poll that did not answer 200."""

    def __init__(self) -> None:
        self.failed: list[float] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._poll, daemon=True)

    def _poll(self) -> None:
        while not self._stop.is_set():
            try:
                code = vm.curl_vm(PROBE[1], PROBE[0])[0]
            except (subprocess.SubprocessError, OSError):
                code = 0  # no answer is downtime too
            if code != 200:
                self.failed.append(time.time())
            self._stop.wait(1)

    def __enter__(self) -> "Downtime":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        self._thread.join()

    def seconds(self) -> int:
        return int(self.failed[-1] - self.failed[0]) + 1 if self.failed else 0


def migrate_measured(results: dict) -> None:
    vm.phase("Migrate")
    text = check_report(["VERDICT: ready"])
    found = re.search(r"\((\d+) MB of images, (\d+) files to shift", text)
    if not found:
        vm.step_fail("read the estimate", text[-2000:])
    results["images_mb"], results["files"] = int(found[1]), int(found[2])
    with Downtime() as down:
        st.run_steps([("userns-migrate", "root", f"{SHIM} userns-migrate", 0)])
    results["downtime_s"] = down.seconds()
    vm.step_pass(f"{results['downtime_s']} s without a 200 from {PROBE[0]}")


def after_migration(when: str) -> list[tuple]:
    return [(f"the daemon is remapped {when}", "root", REMAPPED, 0),
            (f"docker-userns is ok {when}", "root",
             "boxmunge-server health | grep -Eq '^  OK +docker-userns'", 0),
            *seeds_hold(when),
            (f"vmapp serves its upload {when}", "root",
             "curl -sk --resolve vmapp.localhost:443:127.0.0.1 https://vmapp.localhost/ "
             "| grep -qx upload", 0)]


def wait_back(after: str, timeout: int = 300) -> None:
    """The box answers supervisor's ssh again (it went down on purpose)."""
    time.sleep(20)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if st.ssh("root", "docker info >/dev/null").returncode == 0:
                vm.step_pass(f"the box is back after {after}")
                return
        except subprocess.TimeoutExpired:
            pass
        time.sleep(5)
    vm.step_fail(f"the box comes back after {after}", f"no ssh within {timeout} s")


def platform_checks() -> None:
    vm.phase("The platform's own checks, then a reboot")
    st.run_steps([
        *after_migration("after the migration"),
        ("self-test", "deploy", "self-test", 0),
        ("test-restore", "deploy", "test-restore vmdb", 0),
        ("backup-sync", "deploy", "backup-sync", 0),
        ("container-update", "root", "boxmunge-server container-update --force", 0),
        ("cve-scan", "deploy", "security scan vmweb", 0),
        ("the suppression still applies", "deploy", "security vmweb", 0, "CVE-2024-45337"),
        ("reboot", "root", "systemd-run --on-active=2 systemctl reboot", 0),
    ])
    wait_back("the reboot")
    st.run_steps(after_migration("after the reboot"))


def _killer(phase: str, how: str) -> str:
    """Start the migration in its own process group and stop it hard once
    the journal reaches `phase`: SIGKILL to the whole group (the shim and
    the Python core it runs), or a power cut a moment after this script
    has answered."""
    stop = ("kill -9 -- -\"$pg\"" if how == "kill" else
            "setsid sh -c 'sleep 2; echo b > /proc/sysrq-trigger' > /dev/null 2>&1 < /dev/null &")
    return f"""set -e
setsid {SHIM} userns-migrate > /root/userns-killed.log 2>&1 < /dev/null &
pg=$!
for i in $(seq 3000); do
    p=$(python3 -c "import json; print(json.load(open('{JOURNAL}'))['phase'])" 2>/dev/null || true)
    case "$p" in {'|'.join(PHASES[PHASES.index(phase):])}|applied) break ;; esac
    sleep 0.2
done
echo "stopped at $p"
{stop}
"""


def crashes() -> None:
    vm.phase("kill -9 and a power cut in each phase, then resume")
    st.run_steps([("userns-rollback", "root", f"{SHIM} userns-rollback", 0),
                  ("the daemon is back on its old store", "root", NOT_REMAPPED, 0),
                  *seeds_hold("after the rollback")])
    for how in ("kill", "power cut"):
        for phase in PHASES:
            result = st.ssh("root", _killer(phase, "kill" if how == "kill" else "power"))
            vm.step_pass(f"{how} at {phase}: {result.stdout.strip()[-80:]}")
            if how != "kill":
                wait_back(f"a power cut at {phase}")
            st.run_steps([(f"resume after the {how} at {phase}", "root",
                           f"{SHIM} userns-migrate", 0),
                          *after_migration(f"after the {how} at {phase}"),
                          (f"roll back after the {how} at {phase}", "root",
                           f"{SHIM} userns-rollback", 0),
                          *seeds_hold(f"after rolling back the {how} at {phase}")])


def soak_rollback_commit(results: dict) -> None:
    vm.phase("Soak, roll back, migrate again, commit")
    upload2 = "/opt/boxmunge/projects/vmapp/data/uploads/soak.html"
    st.run_steps([
        ("migrate", "root", f"{SHIM} userns-migrate", 0),
        deploy("vmapp", "v3"),
        ("an upload during the soak", "root",
         f"echo soak > {upload2} && chown --reference={upload2.rsplit('/', 1)[0]} {upload2}", 0),
        ("userns-rollback", "root", f"{SHIM} userns-rollback", 0),
        ("the soak's deploy and upload are kept", "root",
         f"grep -qx v3 /opt/boxmunge/projects/vmapp/VERSION && grep -qx soak {upload2}", 0),
        *seeds_hold("after the soak's rollback"),
        ("migrate again", "root", f"{SHIM} userns-migrate", 0),
        ("commit is refused during the soak", "root", f"{SHIM} userns-commit", 1, "soak until"),
        ("end the soak", "root", END_SOAK, 0),
    ])
    before = int(st.ssh("root", STORE_BYTES).stdout.strip())
    st.run_steps([("userns-commit", "root", f"{SHIM} userns-commit", 0),
                  ("rollback is no longer offered", "root", f"{SHIM} userns-rollback", 1,
                   "committed"),
                  *after_migration("after the commit")])
    results["reclaimed_bytes"] = before - int(st.ssh("root", STORE_BYTES).stdout.strip())


def install_old_release(hostname: str, tarball: Path) -> None:
    """0.10.1 through this machine's `boxmunge server-setup`, the host key
    confirmed by the fingerprint read over the test user's ssh (as vm-test)."""
    vm.phase(f"Install boxmunge {st.OLD_VERSION}")
    fingerprint = vm.ssh_run("test", vm.PORTS["ssh_initial"],
                             "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub").stdout.split()[1]
    cmd = ["boxmunge", "server-setup", "test@localhost", "-p", str(vm.PORTS["ssh_initial"]),
           "--email", "test@example.com", "--self-signed-tls", "--yes", "--hostname", hostname,
           "--boxmunge-ssh-port", "922", "--no-aide", "--no-crowdsec", "--no-auto-updates",
           "--local-bundle", str(tarball), "--host-key-fingerprint", fingerprint]
    log = WORK / "server-setup.log"
    with open(log, "w") as out:
        rc = subprocess.run(cmd, stdout=out, stderr=subprocess.STDOUT, check=False).returncode
    if rc != 0:
        vm.step_fail("server-setup exited non-zero", log.read_text()[-3000:])
    vm.step_pass(f"server-setup installed {tarball.name}")
    st.run_steps([(f"{st.OLD_VERSION} is live", "root", st.LIVE_IS_OLD, 0)])


def boot() -> None:
    st.boot()
    vm.check_cloud_init(vm.ssh_run, vm.PORTS["ssh_initial"])
    vm.check_guest_egress(vm.ssh_run, vm.PORTS["ssh_initial"])
    vm.step_pass("the VM resolves and reaches the internet")


def run(flavour: str) -> int:
    start, results = time.time(), {"flavour": flavour}
    WORK.mkdir(parents=True, exist_ok=True)
    try:
        vm.phase(f"Releases: {st.OLD_VERSION} and the beta as {st.BETA_VERSION}")
        old = st.fetch_old_release(WORK)
        shutil.rmtree(WORK / "release", ignore_errors=True)
        (WORK / "release").mkdir()
        st.build_beta_release(WORK / "release")
        boot()
        if flavour == "docker28":
            vm.phase("Docker 28 before boxmunge")
            vm.ssh_run("test", vm.PORTS["ssh_initial"],
                       f"sudo bash -c {shlex.quote(DOCKER28_INSTALL)}")
            vm.step_pass("docker-ce 28.5.2 on overlay2, held")
        install_old_release("boxmunge-userns-test", old)
        with tempfile.TemporaryDirectory() as tmp:
            stage_dir = Path(tmp) / "vm-staging"  # the name INSTALL_HELPERS expects
            stage_dir.mkdir()
            prepare(stage_dir)
        vm.phase("Upgrade to the beta")
        st.run_steps([("upgrade", "root", st.UPGRADE, 0), ("end probation", "root",
                                                           st.END_PROBATION, 0)])
        declare_and_adopt()
        migrate_measured(results)
        platform_checks()
        crashes()
        soak_rollback_commit(results)
    except vm.TestFailure as e:
        print(f"\n  REHEARSAL {flavour} FAILED ({time.time() - start:.0f}s): {e}")
        print(f"  VM left running: ssh {' '.join(vm.SSH_OPTS)} -p {st.PORT} supervisor@localhost")
        print(f"  Tear down with: {sys.argv[0]} teardown")
        return 1
    except Exception as e:  # noqa: BLE001 - infrastructure, not the rehearsal
        print(f"\nINFRASTRUCTURE ERROR: {e}", file=sys.stderr)
        vm.cleanup_vm()
        return 2
    out = WORK / f"results-{flavour}.json"
    out.write_text(json.dumps(results, indent=1) + "\n")
    print(f"\n  REHEARSAL {flavour} PASSED ({time.time() - start:.0f}s); {out}:")
    print(f"  | {flavour} | {results['images_mb']} MB | {results['files']} | "
          f"{results['downtime_s']} s | {results['reclaimed_bytes'] // 10**6} MB |")
    vm.cleanup_vm()
    return 0


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in ("docker29", "docker28", "teardown"):
        print(f"Usage: {sys.argv[0]} docker29|docker28|teardown", file=sys.stderr)
        sys.exit(2)
    if sys.argv[1] == "teardown":
        vm.cmd_teardown()
        sys.exit(0)
    sys.exit(run(sys.argv[1]))


if __name__ == "__main__":
    main()
