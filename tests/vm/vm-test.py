#!/usr/bin/env python3
"""VM-based full-stack integration test for boxmunge.

Boots a fresh Debian 13 VM via QEMU, runs the entire boxmunge workflow,
and verifies everything works — server-setup through backup/restore.

Uses the developer's existing SSH key (agent or ~/.ssh/) — no ephemeral
key generation. This mirrors real usage: you always have an SSH identity
when working on infrastructure tooling.

Usage:
    ./tests/vm/vm-test.py            # Full test run
    ./tests/vm/vm-test.py boot       # Boot VM only (manual exploration)
    ./tests/vm/vm-test.py teardown   # Kill a VM left from a failed run
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration — all port numbers and paths in one place
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CACHE_DIR = REPO_ROOT / ".cache" / "vm"
CLOUD_INIT_DIR = Path(__file__).resolve().parent / "cloud-init"
CANARY_DIR = REPO_ROOT / "canary"

DEBIAN_IMAGE_URL = (
    "https://cloud.debian.org/images/cloud/trixie/daily/latest/"
    "debian-13-generic-amd64-daily.qcow2"
)
DEBIAN_IMAGE = CACHE_DIR / "debian-13-generic-amd64.qcow2"
OVERLAY_DISK = CACHE_DIR / "test-disk.qcow2"
CLOUD_INIT_ISO = CACHE_DIR / "cloud-init.iso"
PID_FILE = CACHE_DIR / "qemu.pid"

# Port forwards: host_port -> VM port
PORTS = {
    "ssh_initial": 12222,   # VM port 22 (pre-setup SSH)
    "ssh_boxmunge": 19220,  # VM port 922 (post-setup boxmunge SSH)
    "http": 18080,          # VM port 80
    "https": 18443,         # VM port 443
}

VM_MEMORY = "2048"
VM_CPUS = "2"

# SSH options for the test script's own connections (not boxmunge CLI).
# No -i needed — the developer's key is in the agent or default location.
SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "LogLevel=ERROR",
    "-o", "ConnectTimeout=5",
]


# ---------------------------------------------------------------------------
# SSH key detection — reuses the same logic as server-setup
# ---------------------------------------------------------------------------

_KEY_PREFERENCE = ["ssh-ed25519", "ssh-ecdsa", "ssh-rsa"]
_KEY_FILES = [".ssh/id_ed25519.pub", ".ssh/id_rsa.pub", ".ssh/id_ecdsa.pub"]


def detect_ssh_pubkey() -> str:
    """Detect the developer's SSH public key (agent first, then files).

    Fails hard if no key found — you need an SSH identity to run this test.
    """
    # Try agent
    result = subprocess.run(
        ["ssh-add", "-L"], capture_output=True, text=True, check=False,
    )
    if result.returncode == 0 and result.stdout.strip():
        keys = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        for pref in _KEY_PREFERENCE:
            for key in keys:
                if key.startswith(pref):
                    return key
        if keys:
            return keys[0]

    # Try files
    home = Path.home()
    for rel in _KEY_FILES:
        path = home / rel
        if path.is_file():
            return path.read_text().strip()

    print("ERROR: No SSH public key found. Add a key to your agent or ~/.ssh/.",
          file=sys.stderr)
    sys.exit(2)


# ---------------------------------------------------------------------------
# Infrastructure helpers
# ---------------------------------------------------------------------------

def clean_known_hosts():
    """Remove stale VM host keys from known_hosts.

    Each VM run generates a new host key on the same forwarded ports.
    Without this, StrictHostKeyChecking=accept-new (used by the boxmunge
    CLI) would reject the new key as a "changed host key".
    """
    for port in (PORTS["ssh_initial"], PORTS["ssh_boxmunge"]):
        subprocess.run(["ssh-keygen", "-R", f"[localhost]:{port}"],
                       capture_output=True, check=False)


def ensure_cache_dir():
    CACHE_DIR.mkdir(parents=True, exist_ok=True)


def download_image():
    """Download Debian cloud image if not cached."""
    if DEBIAN_IMAGE.exists():
        print(f"  Using cached image: {DEBIAN_IMAGE}")
        return
    print(f"  Downloading Debian 13 cloud image...")
    urllib.request.urlretrieve(DEBIAN_IMAGE_URL, DEBIAN_IMAGE)
    print(f"  Saved to {DEBIAN_IMAGE}")


def build_cloud_init_iso(ssh_pubkey: str):
    """Build cloud-init ISO with the developer's SSH public key."""
    # Read template and substitute key
    user_data_template = (CLOUD_INIT_DIR / "user-data").read_text()
    user_data = user_data_template.replace("__SSH_PUBLIC_KEY__", ssh_pubkey)

    meta_data = (CLOUD_INIT_DIR / "meta-data").read_text()

    # Write to temp files for ISO generation
    staging = CACHE_DIR / "cloud-init-staging"
    staging.mkdir(parents=True, exist_ok=True)
    (staging / "user-data").write_text(user_data)
    (staging / "meta-data").write_text(meta_data)

    # Cloud-init requires volume label "cidata" on the ISO
    CLOUD_INIT_ISO.unlink(missing_ok=True)
    subprocess.run(
        [
            "mkisofs",
            "-o", str(CLOUD_INIT_ISO),
            "-V", "cidata",
            "-J", "-R",
            str(staging),
        ],
        check=True, capture_output=True,
    )

    # Cleanup staging
    for f in staging.iterdir():
        f.unlink()
    staging.rmdir()


def create_overlay_disk():
    """Create a copy-on-write overlay backed by the base image."""
    OVERLAY_DISK.unlink(missing_ok=True)
    subprocess.run(
        [
            "qemu-img", "create",
            "-f", "qcow2",
            "-b", str(DEBIAN_IMAGE),
            "-F", "qcow2",
            str(OVERLAY_DISK),
            "20G",
        ],
        check=True, capture_output=True,
    )


def detect_accel() -> str:
    """Detect best QEMU acceleration: hvf (macOS) > tcg (fallback)."""
    result = subprocess.run(
        ["sysctl", "-n", "kern.hv_support"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode == 0 and result.stdout.strip() == "1":
        return "hvf"
    return "tcg"


def launch_qemu():
    """Start QEMU in the background."""
    accel = detect_accel()
    hostfwd = ",".join([
        f"hostfwd=tcp::{PORTS['ssh_initial']}-:22",
        f"hostfwd=tcp::{PORTS['ssh_boxmunge']}-:922",
        f"hostfwd=tcp::{PORTS['http']}-:80",
        f"hostfwd=tcp::{PORTS['https']}-:443",
    ])

    cmd = [
        "qemu-system-x86_64",
        "-m", VM_MEMORY,
        "-smp", VM_CPUS,
        "-accel", accel,
        "-drive", f"file={OVERLAY_DISK},if=virtio",
        "-drive", f"file={CLOUD_INIT_ISO},media=cdrom",
        "-nic", f"user,{hostfwd}",
        "-nographic",
        "-serial", "mon:stdio",
        "-pidfile", str(PID_FILE),
    ]

    # Launch QEMU with stdout/stderr going to a log file
    log_path = CACHE_DIR / "qemu.log"
    log_file = open(log_path, "w")
    proc = subprocess.Popen(
        cmd, stdout=log_file, stderr=log_file,
    )
    # Give QEMU a moment to start and check it's still alive
    for _ in range(5):
        time.sleep(1)
        if proc.poll() is not None:
            log_content = log_path.read_text().strip()
            print(f"ERROR: QEMU exited (code={proc.returncode}). Log:", file=sys.stderr)
            print(log_content, file=sys.stderr)
            sys.exit(2)
    print(f"  QEMU started (pid={proc.pid}, accel={accel})")
    return proc


def wait_for_ssh(port: int, timeout: int = 180) -> bool:
    """Poll SSH until it responds or timeout."""
    deadline = time.time() + timeout
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        result = subprocess.run(
            ["ssh", *SSH_OPTS, "-p", str(port), "test@localhost", "true"],
            capture_output=True, check=False, timeout=10,
        )
        if result.returncode == 0:
            print(f"  SSH ready after {attempt} attempts")
            return True
        time.sleep(3)
    return False


def ssh_run(user: str, port: int, command: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run a command over SSH and return the result."""
    result = subprocess.run(
        ["ssh", *SSH_OPTS, "-p", str(port), f"{user}@localhost", command],
        capture_output=True, text=True, check=False, timeout=300,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"SSH command failed (exit {result.returncode}): {command}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return result


def kill_qemu():
    """Kill QEMU via PID file."""
    if PID_FILE.exists():
        try:
            pid = int(PID_FILE.read_text().strip())
            os.kill(pid, signal.SIGTERM)
            # Wait for process to die
            for _ in range(10):
                try:
                    os.kill(pid, 0)
                    time.sleep(0.5)
                except OSError:
                    break
        except (ValueError, OSError):
            pass
        PID_FILE.unlink(missing_ok=True)


def cleanup_vm():
    """Full cleanup: kill QEMU, remove overlay disk, clean known_hosts."""
    kill_qemu()
    OVERLAY_DISK.unlink(missing_ok=True)
    clean_known_hosts()
    # Keep the base image and cloud-init ISO cached


def verify_target_is_debian(port: int):
    """Safety check: confirm we're talking to a Debian VM, not the Mac host."""
    result = ssh_run("test", port, "cat /etc/os-release", check=False)
    if result.returncode != 0:
        raise RuntimeError("Cannot read /etc/os-release — is this a Debian VM?")
    content = result.stdout.lower()
    if "debian" not in content:
        raise RuntimeError(
            f"SAFETY ABORT: Target does not appear to be Debian.\n"
            f"/etc/os-release contents:\n{result.stdout}\n"
            f"Refusing to proceed — this might be the Mac host!"
        )


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_boot():
    """Boot the VM and leave it running for manual exploration."""
    clean_known_hosts()
    ensure_cache_dir()
    download_image()
    ssh_pubkey = detect_ssh_pubkey()
    build_cloud_init_iso(ssh_pubkey)
    create_overlay_disk()

    print("Launching VM...")
    launch_qemu()

    print("Waiting for SSH...")
    if not wait_for_ssh(PORTS["ssh_initial"]):
        print("ERROR: SSH did not become available within timeout.", file=sys.stderr)
        kill_qemu()
        sys.exit(2)

    verify_target_is_debian(PORTS["ssh_initial"])
    print(f"\nVM is running. Connect with:")
    print(f"  ssh {' '.join(SSH_OPTS)} -p {PORTS['ssh_initial']} test@localhost")
    print(f"\nTo tear down:")
    print(f"  {sys.argv[0]} teardown")


def cmd_teardown():
    """Kill a VM left from a previous run."""
    if PID_FILE.exists():
        print("Killing QEMU...")
        cleanup_vm()
        print("Done.")
    else:
        print("No VM found (no PID file).")


# ---------------------------------------------------------------------------
# Test output helpers
# ---------------------------------------------------------------------------

class TestFailure(Exception):
    """Raised when a test step fails."""
    pass


def phase(name: str):
    """Print a phase header."""
    print(f"\n{'='*60}")
    print(f"  {name}")
    print(f"{'='*60}\n")


def step_pass(description: str):
    print(f"  PASS  {description}")


def step_fail(description: str, detail: str = ""):
    msg = f"  FAIL  {description}"
    if detail:
        msg += f"\n        {detail}"
    print(msg)
    raise TestFailure(f"{description}: {detail}")


def curl_vm(path: str, host_header: str, method: str = "GET", data: str | None = None) -> tuple[int, str]:
    """Make an HTTP request to the VM via port-forwarded HTTPS."""
    cmd = [
        "curl", "-sk",
        "-X", method,
        "-H", f"Host: {host_header}",
        "-w", "\n%{http_code}",
        f"https://localhost:{PORTS['https']}{path}",
    ]
    if data is not None:
        cmd.extend(["-d", data])
    result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=30)
    lines = result.stdout.strip().rsplit("\n", 1)
    if len(lines) == 2:
        body, code = lines
        return int(code), body
    elif len(lines) == 1:
        return int(lines[0]), ""
    return 0, result.stderr


# ---------------------------------------------------------------------------
# Test phases
# ---------------------------------------------------------------------------

def build_server_bundle() -> Path:
    """Build the server bundle tarball from the local repo."""
    # Clean first to ensure we pick up all changes
    subprocess.run(["make", "clean"], cwd=REPO_ROOT, capture_output=True, check=False)
    result = subprocess.run(
        ["make", "bundle"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"make bundle failed:\n{result.stdout}\n{result.stderr}")
    # Find the built bundle
    dist = REPO_ROOT / "dist"
    bundles = sorted(dist.glob("boxmunge-*.tar.gz"))
    if not bundles:
        raise RuntimeError("No bundle found in dist/ after make bundle")
    return bundles[-1]


def phase_1_server_setup(hostname: str):
    """Run boxmunge server-setup against the VM."""
    phase("Phase 1: Server Setup")

    # Build local bundle (no GitHub release exists yet)
    bundle_path = build_server_bundle()
    step_pass(f"Built server bundle: {bundle_path.name}")

    # server-setup auto-detects the SSH key (same key cloud-init installed)
    cmd = [
        "boxmunge",
        "server-setup",
        f"test@localhost",
        "-p", str(PORTS["ssh_initial"]),
        "--email", "test@example.com",
        "--self-signed-tls",
        "--yes",
        "--hostname", hostname,
        "--boxmunge-ssh-port", "922",
        "--no-aide",
        "--no-crowdsec",
        "--no-auto-updates",
        "--local-bundle", str(bundle_path),
    ]

    setup_log = CACHE_DIR / "server-setup.log"
    # Tee to /tmp so user can tail -f /tmp/vm-test.log
    tee_log = Path("/tmp/vm-test.log")
    with open(setup_log, "w") as log_f, open(tee_log, "w") as tee_f:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in proc.stdout:  # type: ignore[union-attr]
            log_f.write(line)
            tee_f.write(line)
            tee_f.flush()
        proc.wait()
    if proc.returncode != 0:
        log_tail = setup_log.read_text()[-2000:]
        step_fail("server-setup exited non-zero", log_tail)
    step_pass("server-setup completed")

    # Verify server state via supervisor SSH (through port 19220 -> VM 922)
    ssh_run("supervisor", PORTS["ssh_boxmunge"],
            "test -f /opt/boxmunge/config/boxmunge.yml")
    step_pass("boxmunge.yml exists")

    ssh_run("supervisor", PORTS["ssh_boxmunge"], "docker info > /dev/null 2>&1")
    step_pass("Docker is running")

    result = ssh_run("supervisor", PORTS["ssh_boxmunge"],
                     "docker ps --format '{{.Names}}'")
    if "boxmunge-caddy" not in result.stdout:
        step_fail("Caddy container not running", result.stdout)
    step_pass("Caddy container is up")

    ssh_run("supervisor", PORTS["ssh_boxmunge"], "id deploy")
    ssh_run("supervisor", PORTS["ssh_boxmunge"], "id supervisor")
    step_pass("deploy and supervisor users exist")


def phase_2_deploy_v1(work_dir: Path, hostname: str):
    """Deploy canary project with VERSION=v1."""
    phase("Phase 2: Deploy v1")

    # Prepare canary copy with v1
    canary_copy = work_dir / "canary"
    if canary_copy.exists():
        shutil.rmtree(canary_copy)
    shutil.copytree(CANARY_DIR, canary_copy)
    (canary_copy / "VERSION").write_text("v1\n")
    step_pass("Canary project prepared with VERSION=v1")

    # Init
    result = subprocess.run(
        [
            "boxmunge",
            "init",
            "--server", "localhost",
            "--port", str(PORTS["ssh_boxmunge"]),
            "--project", "boxmunge-canary",
            "--force",
        ],
        cwd=canary_copy, capture_output=True, text=True, check=False, timeout=60,
    )
    if result.returncode != 0:
        step_fail("boxmunge init failed", result.stdout + result.stderr)
    step_pass("boxmunge init completed")

    # Register project on server (required before first deploy)
    ssh_run("supervisor", PORTS["ssh_boxmunge"], "sudo boxmunge-server project-add boxmunge-canary")
    step_pass("Project registered on server")

    # Build bundle locally
    result = subprocess.run(
        ["boxmunge", "bundle", str(canary_copy)],
        capture_output=True, text=True, check=False, timeout=60,
    )
    if result.returncode != 0:
        step_fail("boxmunge bundle failed", result.stdout + result.stderr)
    # Find the bundle
    bundle_files = sorted(canary_copy.parent.glob("boxmunge-canary-*.tar.gz"),
                          key=lambda f: f.stat().st_mtime)
    if not bundle_files:
        # Check temp dirs
        import glob
        bundle_files = sorted(Path(tempfile.gettempdir()).glob("*/boxmunge-canary-*.tar.gz"),
                              key=lambda f: f.stat().st_mtime)
    if not bundle_files:
        step_fail("No bundle file found after boxmunge bundle")
    bundle = bundle_files[-1]
    step_pass(f"Bundle created: {bundle.name}")

    # Upload bundle to server inbox via test user (deploy user SCP is broken)
    scp_result = subprocess.run(
        ["scp", *SSH_OPTS, "-P", str(PORTS["ssh_boxmunge"]),
         str(bundle), f"test@localhost:/tmp/"],
        capture_output=True, text=True, check=False, timeout=60,
    )
    if scp_result.returncode != 0:
        step_fail("SCP upload failed", scp_result.stderr)
    # Move into inbox as deploy user
    ssh_run("supervisor", PORTS["ssh_boxmunge"],
            f"sudo mv /tmp/{bundle.name} /opt/boxmunge/inbox/ && "
            f"sudo chown deploy:deploy /opt/boxmunge/inbox/{bundle.name}")
    step_pass("Bundle uploaded to inbox")

    # Stage via deploy user
    ssh_run("deploy", PORTS["ssh_boxmunge"], f"stage boxmunge-canary")
    step_pass("boxmunge stage completed")

    # Verify staging is live
    code, body = curl_vm("/healthz", f"staging.{hostname}")
    if code != 200:
        step_fail(f"Staging health check failed (HTTP {code})", body)
    step_pass("Staging is live")

    # Verify staging containers via SSH
    result = ssh_run("supervisor", PORTS["ssh_boxmunge"],
                     "docker ps --format '{{.Names}}' | grep staging")
    if not result.stdout.strip():
        step_fail("No staging containers found")
    step_pass("Staging containers running")

    # Promote
    ssh_run("deploy", PORTS["ssh_boxmunge"], "promote boxmunge-canary")
    step_pass("boxmunge promote completed")

    # Verify production is live
    code, body = curl_vm("/healthz", hostname)
    if code != 200:
        step_fail(f"Production health check failed (HTTP {code})", body)
    step_pass("Production is live")

    # Verify production containers up, staging containers gone
    result = ssh_run("supervisor", PORTS["ssh_boxmunge"],
                     "docker ps --format '{{.Names}}'")
    if "staging" in result.stdout:
        step_fail("Staging containers still running after promote", result.stdout)
    step_pass("Staging containers removed after promote")


def phase_3_stateful_write_v1(hostname: str):
    """Write data and verify version while v1 is deployed."""
    phase("Phase 3: Stateful Write (v1)")

    # Write data
    code, _ = curl_vm("/data", hostname, method="POST", data="alpha")
    if code not in (200, 201):
        step_fail(f"POST /data failed (HTTP {code})")
    step_pass("POST /data 'alpha' succeeded")

    # Read data back
    code, body = curl_vm("/data", hostname)
    if code != 200:
        step_fail(f"GET /data failed (HTTP {code})", body)
    data = json.loads(body)
    if data.get("value") != "alpha":
        step_fail(f"GET /data returned wrong value", f"expected 'alpha', got {data!r}")
    step_pass("GET /data returned 'alpha'")

    # Check version
    code, body = curl_vm("/version", hostname)
    if code != 200:
        step_fail(f"GET /version failed (HTTP {code})", body)
    if body.strip() != "v1":
        step_fail(f"GET /version returned wrong version", f"expected 'v1', got '{body.strip()}'")
    step_pass("GET /version returned 'v1'")


def phase_4_backup(hostname: str) -> str:
    """Run backup and return the snapshot filename."""
    phase("Phase 4: Backup")

    result = ssh_run("supervisor", PORTS["ssh_boxmunge"],
                     "sudo boxmunge-server backup boxmunge-canary")
    if "ERROR" in result.stdout:
        step_fail("Backup command reported error", result.stdout)
    step_pass("Backup command completed")

    # Find the snapshot file
    result = ssh_run("supervisor", PORTS["ssh_boxmunge"],
                     "ls -1t /opt/boxmunge/projects/boxmunge-canary/backups/*.age 2>/dev/null | head -1")
    snapshot = result.stdout.strip()
    if not snapshot:
        step_fail("No backup snapshot found")
    step_pass(f"Backup snapshot created: {os.path.basename(snapshot)}")
    return snapshot


def phase_5_deploy_v2_and_overwrite(work_dir: Path, hostname: str):
    """Redeploy with v2, write new data to overwrite v1 state."""
    phase("Phase 5: Deploy v2 and Overwrite")

    canary_copy = work_dir / "canary"
    (canary_copy / "VERSION").write_text("v2\n")
    step_pass("Updated VERSION to v2")

    # Build, upload, stage, promote v2 (same workaround as phase 2)
    result = subprocess.run(
        ["boxmunge", "bundle", str(canary_copy)],
        capture_output=True, text=True, check=False, timeout=60,
    )
    if result.returncode != 0:
        step_fail("boxmunge bundle (v2) failed", result.stdout + result.stderr)
    bundle_files = sorted(Path(tempfile.gettempdir()).glob("*/boxmunge-canary-*.tar.gz"),
                          key=lambda f: f.stat().st_mtime)
    if not bundle_files:
        step_fail("No v2 bundle file found")
    bundle = bundle_files[-1]

    subprocess.run(
        ["scp", *SSH_OPTS, "-P", str(PORTS["ssh_boxmunge"]),
         str(bundle), f"test@localhost:/tmp/"],
        capture_output=True, check=True, timeout=60,
    )
    ssh_run("supervisor", PORTS["ssh_boxmunge"],
            f"sudo mv /tmp/{bundle.name} /opt/boxmunge/inbox/ && "
            f"sudo chown deploy:deploy /opt/boxmunge/inbox/{bundle.name}")
    ssh_run("deploy", PORTS["ssh_boxmunge"], "stage boxmunge-canary")
    step_pass("boxmunge stage (v2) completed")

    ssh_run("deploy", PORTS["ssh_boxmunge"], "promote boxmunge-canary")
    step_pass("boxmunge promote (v2) completed")

    # Verify v2 is running
    code, body = curl_vm("/version", hostname)
    if body.strip() != "v2":
        step_fail(f"GET /version expected 'v2'", f"got '{body.strip()}'")
    step_pass("GET /version returned 'v2'")

    # Overwrite data
    code, _ = curl_vm("/data", hostname, method="POST", data="bravo")
    if code not in (200, 201):
        step_fail(f"POST /data 'bravo' failed (HTTP {code})")
    step_pass("POST /data 'bravo' succeeded")

    # Verify overwrite
    code, body = curl_vm("/data", hostname)
    data = json.loads(body)
    if data.get("value") != "bravo":
        step_fail(f"GET /data expected 'bravo'", f"got {data!r}")
    step_pass("GET /data returned 'bravo'")


def phase_6_restore_and_verify(work_dir: Path, hostname: str, snapshot: str):
    """Restore from backup and verify v1 state is back."""
    phase("Phase 6: Restore and Verify Rollback")

    # Restore
    snapshot_name = os.path.basename(snapshot)
    result = ssh_run("supervisor", PORTS["ssh_boxmunge"],
                     f"sudo boxmunge-server restore boxmunge-canary {snapshot_name} --yes")
    if "ERROR" in result.stdout:
        step_fail("Restore command reported error", result.stdout)
    step_pass("Restore completed")

    # Re-deploy to bring containers back up from restored state
    # Build v1 bundle, upload, and prod-deploy
    canary_copy = work_dir / "canary"
    (canary_copy / "VERSION").write_text("v1\n")

    result = subprocess.run(
        ["boxmunge", "bundle", str(canary_copy)],
        capture_output=True, text=True, check=False, timeout=60,
    )
    if result.returncode != 0:
        step_fail("boxmunge bundle (restore) failed", result.stdout + result.stderr)
    bundle_files = sorted(Path(tempfile.gettempdir()).glob("*/boxmunge-canary-*.tar.gz"),
                          key=lambda f: f.stat().st_mtime)
    bundle = bundle_files[-1]

    subprocess.run(
        ["scp", *SSH_OPTS, "-P", str(PORTS["ssh_boxmunge"]),
         str(bundle), f"test@localhost:/tmp/"],
        capture_output=True, check=True, timeout=60,
    )
    ssh_run("supervisor", PORTS["ssh_boxmunge"],
            f"sudo mv /tmp/{bundle.name} /opt/boxmunge/inbox/ && "
            f"sudo chown deploy:deploy /opt/boxmunge/inbox/{bundle.name}")
    ssh_run("deploy", PORTS["ssh_boxmunge"], "prod-deploy boxmunge-canary")
    step_pass("prod-deploy after restore completed")

    # Wait for app to be ready
    time.sleep(5)

    # Verify restored version
    code, body = curl_vm("/version", hostname)
    if body.strip() != "v1":
        step_fail(f"GET /version expected 'v1' after restore", f"got '{body.strip()}'")
    step_pass("GET /version returned 'v1' (restored)")

    # Verify restored data
    code, body = curl_vm("/data", hostname)
    data = json.loads(body)
    if data.get("value") != "alpha":
        step_fail(f"GET /data expected 'alpha' after restore", f"got {data!r}")
    step_pass("GET /data returned 'alpha' (restored, not 'bravo')")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def cmd_run():
    """Full test run."""
    start_time = time.time()
    hostname = "boxmunge-test"

    # Setup signal handler for clean Ctrl-C
    def on_signal(sig, frame):
        print("\n\nInterrupted — cleaning up...")
        cleanup_vm()
        sys.exit(2)
    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    try:
        phase("Setup: Preparing VM")

        clean_known_hosts()
        ensure_cache_dir()
        download_image()
        ssh_pubkey = detect_ssh_pubkey()
        step_pass(f"Using SSH key: {ssh_pubkey[:30]}...")
        build_cloud_init_iso(ssh_pubkey)
        create_overlay_disk()

        print("Launching QEMU...")
        launch_qemu()

        print("Waiting for SSH...")
        if not wait_for_ssh(PORTS["ssh_initial"]):
            print("ERROR: SSH did not become available.", file=sys.stderr)
            sys.exit(2)

        verify_target_is_debian(PORTS["ssh_initial"])
        step_pass("VM booted and verified as Debian")

        # Run test phases
        work_dir = Path(tempfile.mkdtemp(prefix="boxmunge-vm-test-"))

        phase_1_server_setup(hostname)
        phase_2_deploy_v1(work_dir, hostname)
        phase_3_stateful_write_v1(hostname)
        snapshot = phase_4_backup(hostname)
        phase_5_deploy_v2_and_overwrite(work_dir, hostname)
        phase_6_restore_and_verify(work_dir, hostname, snapshot)

        # Success
        elapsed = time.time() - start_time
        print(f"\n{'='*60}")
        print(f"  ALL PHASES PASSED ({elapsed:.0f}s)")
        print(f"{'='*60}")
        cleanup_vm()
        sys.exit(0)

    except TestFailure as e:
        elapsed = time.time() - start_time
        print(f"\n{'='*60}")
        print(f"  TEST FAILED ({elapsed:.0f}s)")
        print(f"  {e}")
        print(f"{'='*60}")
        print(f"\nVM left running for debugging:")
        print(f"  ssh {' '.join(SSH_OPTS)} -p {PORTS['ssh_initial']} test@localhost")
        print(f"  ssh {' '.join(SSH_OPTS)} -p {PORTS['ssh_boxmunge']} supervisor@localhost")
        print(f"\nTo tear down:")
        print(f"  {sys.argv[0]} teardown")
        sys.exit(1)

    except Exception as e:
        print(f"\nINFRASTRUCTURE ERROR: {e}", file=sys.stderr)
        cleanup_vm()
        sys.exit(2)


def main():
    if len(sys.argv) > 1:
        subcmd = sys.argv[1]
        if subcmd == "boot":
            cmd_boot()
        elif subcmd == "teardown":
            cmd_teardown()
        else:
            print(f"Unknown subcommand: {subcmd}", file=sys.stderr)
            print(f"Usage: {sys.argv[0]} [boot|teardown]", file=sys.stderr)
            sys.exit(2)
    else:
        cmd_run()


if __name__ == "__main__":
    main()
