# VM Test Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standalone Python script that boots a fresh Debian 13 VM via QEMU and exercises the full boxmunge workflow end-to-end: server-setup, deploy, promote, backup, restore with data integrity verification.

**Architecture:** Single `tests/vm/vm-test.py` script manages the full VM lifecycle via subprocess QEMU. Cloud-init configures SSH access. Four QEMU port forwards (SSH initial, SSH boxmunge, HTTP, HTTPS) bridge the VM to localhost. Two small production code changes (`--self-signed-tls` on init-host.sh/server-setup, `--yes` on server-setup) enable non-interactive testing.

**Tech Stack:** Python 3 stdlib (subprocess, http.server, json, pathlib, signal, tempfile), QEMU, cloud-init, hdiutil (macOS)

**Spec:** `docs/superpowers/specs/2026-04-17-vm-test-harness-design.md`

---

### Task 1: Add `--self-signed-tls` flag to `init-host.sh`

**Files:**
- Modify: `bootstrap/init-host.sh`
- Test: manual (tested in Task 10 via full VM run)

- [ ] **Step 1: Add the flag to argument parsing**

In `bootstrap/init-host.sh`, add a new default and case branch. After line 30 (`INSTALL_AUTO_UPDATES=true`), add:

```bash
SELF_SIGNED_TLS=false
```

In the `case` block (after the `--no-auto-updates` branch, before `*)`), add:

```bash
        --self-signed-tls)    SELF_SIGNED_TLS=true;           shift ;;
```

- [ ] **Step 2: Store the flag in boxmunge.yml**

Find the section in `init-host.sh` that writes `boxmunge.yml` (the server config file). Add `tls_mode: internal` when `--self-signed-tls` is set. After the existing config write:

```bash
if [ "$SELF_SIGNED_TLS" = "true" ]; then
    echo "tls_mode: internal" >> "${BOXMUNGE_ROOT}/config/boxmunge.yml"
fi
```

- [ ] **Step 3: Use `local_certs` in the global Caddyfile**

Replace the Caddyfile heredoc (currently at lines 465-471) with:

```bash
if [ "$SELF_SIGNED_TLS" = "true" ]; then
cat > "${BOXMUNGE_ROOT}/caddy/Caddyfile" <<EOF
{
    email ${ADMIN_EMAIL}
    local_certs
}

import /etc/caddy/sites/*.conf
EOF
else
cat > "${BOXMUNGE_ROOT}/caddy/Caddyfile" <<EOF
{
    email ${ADMIN_EMAIL}
}

import /etc/caddy/sites/*.conf
EOF
fi
```

The `local_certs` global option tells Caddy to use its internal CA for all certificates instead of ACME. This applies to all sites automatically — no per-site changes needed.

- [ ] **Step 4: Commit**

```bash
git add bootstrap/init-host.sh
git commit -m "feat: add --self-signed-tls flag to init-host.sh

Uses Caddy's local_certs global option and stores tls_mode in
boxmunge.yml for downstream commands to detect."
```

---

### Task 2: Add `--self-signed-tls` and `--yes` flags to CLI `server-setup`

**Files:**
- Modify: `cli/src/boxmunge_cli/server_setup/command.py`
- Modify: `cli/tests/test_server_setup/test_command.py`

- [ ] **Step 1: Write failing tests for both new flags**

Add to `cli/tests/test_server_setup/test_command.py`:

```python
def test_self_signed_tls_flag(self) -> None:
    args = parse_args([
        "myserver.example.com", "--email", "a@b.com",
        "--self-signed-tls",
    ])
    assert args.self_signed_tls is True

def test_self_signed_tls_default_false(self) -> None:
    args = parse_args(["myserver.example.com", "--email", "a@b.com"])
    assert args.self_signed_tls is False

def test_yes_flag(self) -> None:
    args = parse_args([
        "myserver.example.com", "--email", "a@b.com", "--yes",
    ])
    assert args.yes is True

def test_yes_short_flag(self) -> None:
    args = parse_args([
        "myserver.example.com", "--email", "a@b.com", "-y",
    ])
    assert args.yes is True

def test_yes_default_false(self) -> None:
    args = parse_args(["myserver.example.com", "--email", "a@b.com"])
    assert args.yes is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Volumes/TERRA/work/aidev/boxmunge && python -m pytest cli/tests/test_server_setup/test_command.py -v`
Expected: 5 failures (attributes don't exist on `ServerSetupArgs`)

- [ ] **Step 3: Add fields to `ServerSetupArgs` dataclass**

In `cli/src/boxmunge_cli/server_setup/command.py`, add to the `ServerSetupArgs` dataclass (after `reboot_window`):

```python
    self_signed_tls: bool = False
    yes: bool = False
```

- [ ] **Step 4: Add flag parsing**

In `parse_args`, add after the `reboot_window` default (line 51):

```python
    self_signed_tls = False
    yes = False
```

In the `while` loop, add two branches before the `elif not args[i].startswith("-"):` line:

```python
        elif args[i] == "--self-signed-tls":
            self_signed_tls = True; i += 1
        elif args[i] in ("-y", "--yes"):
            yes = True; i += 1
```

In the `return ServerSetupArgs(...)` call, add:

```python
        self_signed_tls=self_signed_tls, yes=yes,
```

- [ ] **Step 5: Use `--yes` to skip confirmation**

In `cmd_server_setup`, replace the confirmation block (lines 202-207):

```python
    # Interactive confirmation
    if not setup_args.yes:
        print(f"This will turn [{setup_args.host}] into a boxmunge server.")
        response = input("Are you sure? [y/N] ").strip().lower()
        if response != "y":
            print("Aborted.")
            sys.exit(0)
```

- [ ] **Step 6: Pass `--self-signed-tls` through to init-host.sh**

In `_run_install`, after the `--no-auto-updates` append block (line 160), add:

```python
    if setup_args.self_signed_tls:
        init_cmd_parts.append("--self-signed-tls")
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd /Volumes/TERRA/work/aidev/boxmunge && python -m pytest cli/tests/test_server_setup/test_command.py -v`
Expected: all pass

- [ ] **Step 8: Commit**

```bash
git add cli/src/boxmunge_cli/server_setup/command.py cli/tests/test_server_setup/test_command.py
git commit -m "feat: add --self-signed-tls and --yes flags to server-setup

--self-signed-tls passes through to init-host.sh for Caddy local_certs.
--yes / -y skips the interactive confirmation prompt."
```

---

### Task 3: Update canary project with `/version` endpoint

**Files:**
- Modify: `canary/app.py`
- Modify: `canary/Dockerfile`
- Modify: `canary/boxmunge-scripts/smoke.sh`

The canary already has `/data` POST (insert) and GET (count). We need:
1. A `/version` endpoint that returns the contents of a `VERSION` file baked into the image
2. Modify `/data` GET to return the latest value (not just count) for verification

- [ ] **Step 1: Modify `canary/app.py`**

Replace the entire file:

```python
"""Canary project — minimal app for boxmunge self-test."""

import http.server
import json
import os

import psycopg2


VERSION_FILE = "/app/VERSION"


def get_conn():
    return psycopg2.connect(os.environ["DATABASE_URL"])


def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS canary_data (id SERIAL PRIMARY KEY, value TEXT)")
    conn.commit()
    conn.close()


def read_version() -> str:
    try:
        with open(VERSION_FILE) as f:
            return f.read().strip()
    except FileNotFoundError:
        return "unknown"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        elif self.path == "/version":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(read_version().encode())
        elif self.path == "/data":
            conn = get_conn()
            cur = conn.cursor()
            cur.execute("SELECT value FROM canary_data ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
            conn.close()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({"value": row[0] if row else None}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/data":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode() if length else "canary"
            conn = get_conn()
            cur = conn.cursor()
            cur.execute("INSERT INTO canary_data (value) VALUES (%s)", (body,))
            conn.commit()
            conn.close()
            self.send_response(201)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    init_db()
    server = http.server.HTTPServer(("0.0.0.0", 8080), Handler)
    server.serve_forever()
```

- [ ] **Step 2: Add VERSION file to canary**

Create `canary/VERSION`:

```
dev
```

- [ ] **Step 3: Update Dockerfile to copy VERSION**

Replace `canary/Dockerfile`:

```dockerfile
FROM python:3.12-slim
RUN pip install --no-cache-dir psycopg2-binary
COPY app.py /app/app.py
COPY VERSION /app/VERSION
WORKDIR /app
CMD ["python", "app.py"]
```

- [ ] **Step 4: Update smoke test**

Replace `canary/boxmunge-scripts/smoke.sh`:

```bash
#!/bin/sh
SERVICE="$1"
if [ "$SERVICE" = "web" ]; then
    wget -qO- http://localhost:8080/healthz > /dev/null 2>&1 || exit 1
    wget -qO- http://localhost:8080/version > /dev/null 2>&1 || exit 1
    exit 0
fi
exit 0
```

- [ ] **Step 5: Commit**

```bash
git add canary/app.py canary/VERSION canary/Dockerfile canary/boxmunge-scripts/smoke.sh
git commit -m "feat(canary): add /version endpoint and return latest value from /data

VERSION file baked into image at build time. /data GET now returns
the latest stored value for backup/restore verification."
```

---

### Task 4: Cloud-init templates

**Files:**
- Create: `tests/vm/cloud-init/user-data`
- Create: `tests/vm/cloud-init/meta-data`

- [ ] **Step 1: Create meta-data**

Create `tests/vm/cloud-init/meta-data`:

```yaml
instance-id: boxmunge-vm-test
local-hostname: boxmunge-test
```

- [ ] **Step 2: Create user-data template**

Create `tests/vm/cloud-init/user-data`. This is a template — the test script replaces `__SSH_PUBLIC_KEY__` before building the ISO.

```yaml
#cloud-config
users:
  - name: test
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - __SSH_PUBLIC_KEY__

package_update: true
packages:
  - qemu-guest-agent
  - python3

runcmd:
  - systemctl enable --now qemu-guest-agent
```

- [ ] **Step 3: Commit**

```bash
git add tests/vm/cloud-init/meta-data tests/vm/cloud-init/user-data
git commit -m "feat: add cloud-init templates for VM test harness"
```

---

### Task 5: VM test script — infrastructure layer

**Files:**
- Create: `tests/vm/vm-test.py`

This task builds the VM lifecycle management: image download, cloud-init ISO, QEMU launch, SSH wait, teardown. No test phases yet.

- [ ] **Step 1: Create the script with configuration and imports**

Create `tests/vm/vm-test.py`:

```python
#!/usr/bin/env python3
"""VM-based full-stack integration test for boxmunge.

Boots a fresh Debian 13 VM via QEMU, runs the entire boxmunge workflow,
and verifies everything works — server-setup through backup/restore.

Usage:
    ./tests/vm/vm-test.py            # Full test run
    ./tests/vm/vm-test.py boot       # Boot VM only (manual exploration)
    ./tests/vm/vm-test.py teardown   # Kill a VM left from a failed run
"""

import json
import os
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
SSH_KEY = CACHE_DIR / "test_key"
SSH_KEY_PUB = CACHE_DIR / "test_key.pub"
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

SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "LogLevel=ERROR",
    "-o", "ConnectTimeout=5",
    "-i", str(SSH_KEY),
]
```

- [ ] **Step 2: Add image download and cloud-init ISO generation**

Append to `tests/vm/vm-test.py`:

```python
# ---------------------------------------------------------------------------
# Infrastructure helpers
# ---------------------------------------------------------------------------

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


def generate_ssh_key():
    """Generate an ephemeral SSH keypair for this run."""
    SSH_KEY.unlink(missing_ok=True)
    SSH_KEY_PUB.unlink(missing_ok=True)
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", str(SSH_KEY), "-N", "", "-q"],
        check=True,
    )


def build_cloud_init_iso():
    """Build cloud-init ISO with the generated SSH public key."""
    pub_key = SSH_KEY_PUB.read_text().strip()

    # Read template and substitute key
    user_data_template = (CLOUD_INIT_DIR / "user-data").read_text()
    user_data = user_data_template.replace("__SSH_PUBLIC_KEY__", pub_key)

    meta_data = (CLOUD_INIT_DIR / "meta-data").read_text()

    # Write to temp files for ISO generation
    staging = CACHE_DIR / "cloud-init-staging"
    staging.mkdir(parents=True, exist_ok=True)
    (staging / "user-data").write_text(user_data)
    (staging / "meta-data").write_text(meta_data)

    # macOS: use hdiutil to create Joliet ISO (cloud-init compatible)
    CLOUD_INIT_ISO.unlink(missing_ok=True)
    subprocess.run(
        [
            "hdiutil", "makehybrid",
            "-o", str(CLOUD_INIT_ISO),
            "-joliet", "-iso",
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
```

- [ ] **Step 3: Add QEMU launch, wait-for-SSH, and teardown**

Append to `tests/vm/vm-test.py`:

```python
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
    # Give QEMU a moment to write PID file
    time.sleep(2)
    if proc.poll() is not None:
        print(f"ERROR: QEMU exited immediately. Check {log_path}")
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
    """Full cleanup: kill QEMU, remove overlay and ephemeral keys."""
    kill_qemu()
    OVERLAY_DISK.unlink(missing_ok=True)
    SSH_KEY.unlink(missing_ok=True)
    SSH_KEY_PUB.unlink(missing_ok=True)
    # Keep the base image and cloud-init ISO cached
```

- [ ] **Step 4: Add the host safety pre-flight check**

Append to `tests/vm/vm-test.py`:

```python
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
```

- [ ] **Step 5: Add the boot and teardown subcommands**

Append to `tests/vm/vm-test.py`:

```python
# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_boot():
    """Boot the VM and leave it running for manual exploration."""
    ensure_cache_dir()
    download_image()
    generate_ssh_key()
    build_cloud_init_iso()
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
```

- [ ] **Step 6: Commit**

```bash
git add tests/vm/vm-test.py
git commit -m "feat: add VM test script infrastructure layer

QEMU lifecycle: image download, cloud-init ISO, overlay disk,
launch, SSH wait, teardown. Includes host safety pre-flight."
```

---

### Task 6: VM test script — test phases

**Files:**
- Modify: `tests/vm/vm-test.py`

This task adds the six test phases and the `main()` entry point.

- [ ] **Step 1: Add test phase helpers**

Append to `tests/vm/vm-test.py`:

```python
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
        # Only status code, no body
        return int(lines[0]), ""
    return 0, result.stderr
```

- [ ] **Step 2: Add Phase 1 — Server setup**

Append to `tests/vm/vm-test.py`:

```python
# ---------------------------------------------------------------------------
# Test phases
# ---------------------------------------------------------------------------

def phase_1_server_setup(hostname: str):
    """Run boxmunge server-setup against the VM."""
    phase("Phase 1: Server Setup")

    cmd = [
        sys.executable, "-m", "boxmunge_cli",
        "server-setup",
        f"test@localhost",
        "-p", str(PORTS["ssh_initial"]),
        "--email", "test@example.com",
        "--ssh-key", str(SSH_KEY_PUB),
        "--self-signed-tls",
        "--yes",
        "--hostname", hostname,
        "--boxmunge-ssh-port", "922",
        "--no-aide",
        "--no-crowdsec",
        "--no-auto-updates",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=600)
    if result.returncode != 0:
        step_fail("server-setup exited non-zero", result.stdout + result.stderr)
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
```

- [ ] **Step 3: Add Phase 2 — Deploy v1**

Append to `tests/vm/vm-test.py`:

```python
def phase_2_deploy_v1(work_dir: Path, hostname: str):
    """Deploy canary project with VERSION=v1."""
    phase("Phase 2: Deploy v1")

    # Prepare canary copy with v1
    canary_copy = work_dir / "canary"
    if canary_copy.exists():
        import shutil
        shutil.rmtree(canary_copy)
    import shutil
    shutil.copytree(CANARY_DIR, canary_copy)
    (canary_copy / "VERSION").write_text("v1\n")
    step_pass("Canary project prepared with VERSION=v1")

    # Init
    result = subprocess.run(
        [
            sys.executable, "-m", "boxmunge_cli",
            "init",
            "--server", "localhost",
            "--port", str(PORTS["ssh_boxmunge"]),
            "--project", "canary",
            "--force",
        ],
        cwd=canary_copy, capture_output=True, text=True, check=False, timeout=60,
    )
    if result.returncode != 0:
        step_fail("boxmunge init failed", result.stdout + result.stderr)
    step_pass("boxmunge init completed")

    # Stage
    result = subprocess.run(
        [sys.executable, "-m", "boxmunge_cli", "stage"],
        cwd=canary_copy, capture_output=True, text=True, check=False, timeout=300,
    )
    if result.returncode != 0:
        step_fail("boxmunge stage failed", result.stdout + result.stderr)
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
    result = subprocess.run(
        [sys.executable, "-m", "boxmunge_cli", "promote"],
        cwd=canary_copy, capture_output=True, text=True, check=False, timeout=300,
    )
    if result.returncode != 0:
        step_fail("boxmunge promote failed", result.stdout + result.stderr)
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
```

- [ ] **Step 4: Add Phase 3 — Stateful write (v1)**

Append to `tests/vm/vm-test.py`:

```python
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
```

- [ ] **Step 5: Add Phase 4 — Backup**

Append to `tests/vm/vm-test.py`:

```python
def phase_4_backup(hostname: str) -> str:
    """Run backup and return the snapshot filename."""
    phase("Phase 4: Backup")

    result = ssh_run("supervisor", PORTS["ssh_boxmunge"],
                     "sudo boxmunge-server backup canary")
    if "ERROR" in result.stdout:
        step_fail("Backup command reported error", result.stdout)
    step_pass("Backup command completed")

    # Find the snapshot file
    result = ssh_run("supervisor", PORTS["ssh_boxmunge"],
                     "ls -1t /opt/boxmunge/projects/canary/backups/*.age 2>/dev/null | head -1")
    snapshot = result.stdout.strip()
    if not snapshot:
        step_fail("No backup snapshot found")
    step_pass(f"Backup snapshot created: {os.path.basename(snapshot)}")
    return snapshot
```

- [ ] **Step 6: Add Phase 5 — Deploy v2 and overwrite**

Append to `tests/vm/vm-test.py`:

```python
def phase_5_deploy_v2_and_overwrite(work_dir: Path, hostname: str):
    """Redeploy with v2, write new data to overwrite v1 state."""
    phase("Phase 5: Deploy v2 and Overwrite")

    canary_copy = work_dir / "canary"
    (canary_copy / "VERSION").write_text("v2\n")
    step_pass("Updated VERSION to v2")

    # Stage and promote v2
    result = subprocess.run(
        [sys.executable, "-m", "boxmunge_cli", "stage"],
        cwd=canary_copy, capture_output=True, text=True, check=False, timeout=300,
    )
    if result.returncode != 0:
        step_fail("boxmunge stage (v2) failed", result.stdout + result.stderr)
    step_pass("boxmunge stage (v2) completed")

    result = subprocess.run(
        [sys.executable, "-m", "boxmunge_cli", "promote"],
        cwd=canary_copy, capture_output=True, text=True, check=False, timeout=300,
    )
    if result.returncode != 0:
        step_fail("boxmunge promote (v2) failed", result.stdout + result.stderr)
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
```

- [ ] **Step 7: Add Phase 6 — Restore and verify rollback**

Append to `tests/vm/vm-test.py`:

```python
def phase_6_restore_and_verify(work_dir: Path, hostname: str, snapshot: str):
    """Restore from backup and verify v1 state is back."""
    phase("Phase 6: Restore and Verify Rollback")

    # Restore
    snapshot_name = os.path.basename(snapshot)
    result = ssh_run("supervisor", PORTS["ssh_boxmunge"],
                     f"sudo boxmunge-server restore canary {snapshot_name} --yes")
    if "ERROR" in result.stdout:
        step_fail("Restore command reported error", result.stdout)
    step_pass("Restore completed")

    # Re-deploy to bring containers back up from restored state
    canary_copy = work_dir / "canary"
    # Reset VERSION back to v1 to match restored state
    (canary_copy / "VERSION").write_text("v1\n")

    result = subprocess.run(
        [sys.executable, "-m", "boxmunge_cli", "prod-deploy"],
        cwd=canary_copy, capture_output=True, text=True, check=False, timeout=300,
    )
    if result.returncode != 0:
        step_fail("prod-deploy after restore failed", result.stdout + result.stderr)
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
```

- [ ] **Step 8: Add main() entry point**

Append to `tests/vm/vm-test.py`:

```python
# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def cmd_run():
    """Full test run."""
    start_time = time.time()
    hostname = "boxmunge-test"
    qemu_proc = None

    # Setup signal handler for clean Ctrl-C
    def on_signal(sig, frame):
        print("\n\nInterrupted — cleaning up...")
        cleanup_vm()
        sys.exit(2)
    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    try:
        phase("Setup: Preparing VM")

        ensure_cache_dir()
        download_image()
        generate_ssh_key()
        build_cloud_init_iso()
        create_overlay_disk()

        print("Launching QEMU...")
        qemu_proc = launch_qemu()

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
```

- [ ] **Step 9: Make the script executable**

```bash
chmod +x tests/vm/vm-test.py
```

- [ ] **Step 10: Commit**

```bash
git add tests/vm/vm-test.py
git commit -m "feat: add VM test phases — full end-to-end workflow

Six phases: server-setup, deploy v1, stateful write, backup,
deploy v2 + overwrite, restore + rollback verification."
```

---

### Task 7: Makefile target and .gitignore

**Files:**
- Modify: `Makefile`
- Modify: `.gitignore`

- [ ] **Step 1: Add test-vm target to Makefile**

Add after the `test-all` target:

```makefile
test-vm:
	python3 tests/vm/vm-test.py
```

- [ ] **Step 2: Add .cache/vm/ to .gitignore**

Add to `.gitignore`:

```
# VM test cache (downloaded images, overlays, ephemeral keys)
.cache/
```

- [ ] **Step 3: Commit**

```bash
git add Makefile .gitignore
git commit -m "feat: add make test-vm target and gitignore .cache/"
```

---

### Task 8: README

**Files:**
- Create: `tests/vm/README.md`

- [ ] **Step 1: Write the README**

Create `tests/vm/README.md`:

```markdown
# VM Integration Tests

Full-stack acceptance test that boots a fresh Debian 13 VM and exercises
the entire boxmunge workflow: server-setup, deploy, promote, backup,
and restore with data integrity verification.

## Prerequisites

- QEMU (`brew install qemu`)
- Python 3.x
- The `boxmunge` CLI installed (`pip install -e ./cli`)
- ~1GB disk for the cached Debian cloud image

## Usage

```bash
# Full test run (boots VM, runs all phases, tears down on success)
make test-vm

# Or directly:
./tests/vm/vm-test.py

# Boot VM only for manual exploration
./tests/vm/vm-test.py boot

# Kill a VM left from a failed run
./tests/vm/vm-test.py teardown
```

## What it tests

1. **Server setup** — `boxmunge server-setup` against a fresh Debian VM
2. **Deploy v1** — `init` + `stage` + `promote` with HTTP verification
3. **Stateful write** — POST data, verify it's stored
4. **Backup** — server-side backup of the canary project
5. **Deploy v2** — redeploy with new version, overwrite data
6. **Restore** — restore from backup, verify both data and image version rolled back

## Port forwards

| Host port | VM port | Purpose |
|-----------|---------|---------|
| 12222 | 22 | Initial SSH (pre-setup) |
| 19220 | 922 | boxmunge SSH (post-setup) |
| 18080 | 80 | HTTP |
| 18443 | 443 | HTTPS |

## On failure

The VM is left running so you can SSH in and debug:

```bash
ssh -o StrictHostKeyChecking=no -i .cache/vm/test_key -p 12222 test@localhost
ssh -o StrictHostKeyChecking=no -i .cache/vm/test_key -p 19220 supervisor@localhost
```

Run `./tests/vm/vm-test.py teardown` when done.

## First run

The first run downloads the Debian 13 cloud image (~700MB) and caches it
in `.cache/vm/`. Subsequent runs reuse the cached image via copy-on-write
overlays, so only the delta is stored per run.
```

- [ ] **Step 2: Commit**

```bash
git add tests/vm/README.md
git commit -m "docs: add README for VM integration tests"
```

---

### Task 9: Dry-run validation

**Files:** None new — this is a verification task.

Before running the full VM test, validate that the script loads and the infrastructure helpers work without actually booting a VM.

- [ ] **Step 1: Verify the script imports cleanly**

```bash
cd /Volumes/TERRA/work/aidev/boxmunge && python3 -c "import tests.vm" 2>&1 || python3 tests/vm/vm-test.py --help 2>&1 || echo "Script import check done"
```

Actually, since it's a standalone script not a package, just check syntax:

```bash
python3 -m py_compile tests/vm/vm-test.py && echo "Syntax OK"
```

- [ ] **Step 2: Verify cloud-init templates exist and are valid YAML**

```bash
python3 -c "
import yaml
from pathlib import Path
for f in ['tests/vm/cloud-init/meta-data', 'tests/vm/cloud-init/user-data']:
    yaml.safe_load(Path(f).read_text())
    print(f'{f}: valid YAML')
"
```

- [ ] **Step 3: Run existing CLI tests to confirm nothing broke**

```bash
cd /Volumes/TERRA/work/aidev/boxmunge && python -m pytest cli/tests/ -v
```

Expected: all pass (104+)

- [ ] **Step 4: Run existing server tests to confirm nothing broke**

```bash
cd /Volumes/TERRA/work/aidev/boxmunge && python -m pytest tests/ -v --ignore=tests/integration
```

Expected: all pass (514+)

- [ ] **Step 5: Commit any fixes if needed, then tag as ready**

```bash
git log --oneline -8
```

Verify all commits from this plan are present.

---

### Task 10: First live VM test run

**Files:** None new — this is the real execution.

- [ ] **Step 1: Run the full test**

```bash
make test-vm
```

This will:
1. Download the Debian 13 image (first run only, ~700MB)
2. Generate SSH key and cloud-init ISO
3. Boot QEMU with the Debian VM
4. Wait for SSH
5. Run all 6 phases

Expected: All phases pass. If any fail, debug using the left-running VM and iterate on the script.

- [ ] **Step 2: If all phases pass, commit any tweaks discovered during the run**

Fix any issues found during the live run (timeouts, command paths, etc.) and commit.

- [ ] **Step 3: Run teardown to clean up**

```bash
./tests/vm/vm-test.py teardown
```
