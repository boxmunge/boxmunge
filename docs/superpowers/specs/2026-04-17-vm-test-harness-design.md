# VM-Based Full-Stack Integration Test Harness

## Overview

A standalone Python script that boots a fresh Debian 13 VM via QEMU, runs the entire boxmunge workflow end-to-end, and verifies everything works — from server setup through deployment, promotion, backup, and restore. Designed as a manual pre-release gate, automatable in CI later.

## File Layout

```
tests/vm/
├── vm-test.py              # Main script (executable)
├── cloud-init/
│   ├── user-data           # Cloud-init: user, SSH key, sudo, guest agent
│   └── meta-data           # Cloud-init: instance identity
└── README.md               # Prerequisites, usage, what it tests

.cache/vm/                  # Gitignored
├── debian-13-generic-amd64.qcow2   # Base image (downloaded once)
├── test-disk.qcow2         # COW overlay (per-run)
├── cloud-init.iso          # Generated ISO
├── test_key / test_key.pub # Ephemeral SSH keypair
└── qemu.pid                # QEMU process ID
```

**Invocation:**

```bash
./tests/vm/vm-test.py           # Full run
./tests/vm/vm-test.py teardown  # Kill a VM left from a failed run
./tests/vm/vm-test.py boot      # Boot VM only (for manual exploration)
make test-vm                    # Makefile target
```

## VM Lifecycle

### Image sourcing

- Debian 13 (Trixie) generic cloud image in QCOW2 format from `cloud.debian.org`
- Downloaded once to `.cache/vm/debian-13-generic-amd64.qcow2`
- Each run creates a copy-on-write overlay `.cache/vm/test-disk.qcow2` backed by the base image — base stays pristine, boot is fast

### Cloud-init

- `user-data` creates a `test` user with a freshly generated SSH keypair, enables passwordless sudo, installs `qemu-guest-agent`
- `meta-data` sets a fixed instance ID
- Baked into an ISO at `.cache/vm/cloud-init.iso` using `hdiutil makehybrid` (macOS built-in, Joliet format)
- SSH keypair generated per-run to `.cache/vm/test_key` and `.cache/vm/test_key.pub`

### QEMU launch

```
qemu-system-x86_64 \
  -m 2048 -smp 2 \
  -drive file=.cache/vm/test-disk.qcow2,if=virtio \
  -drive file=.cache/vm/cloud-init.iso,media=cdrom \
  -nic user,hostfwd=tcp::12222-:22,hostfwd=tcp::19220-:922,hostfwd=tcp::18080-:80,hostfwd=tcp::18443-:443 \
  -nographic -serial mon:stdio \
  -pidfile .cache/vm/qemu.pid
```

- **User-mode networking** — no root, no bridge config
- **Four port forwards:**
  - 12222 → 22 (initial SSH for server-setup)
  - 19220 → 922 (boxmunge SSH post-setup)
  - 18080 → 80 (HTTP)
  - 18443 → 443 (HTTPS)
- **Acceleration:** `-accel hvf` if Hypervisor.framework available, otherwise `-accel tcg` (software emulation)
- Port numbers chosen high to avoid collisions

### Wait-for-ready

Poll SSH on port 12222 with short timeout, up to 120s. Ready when `ssh test@localhost -p 12222 true` succeeds.

### Teardown

- **On success:** kill QEMU via PID file, remove overlay disk, remove ephemeral keys
- **On failure:** print which phase/step failed, print SSH command to connect, leave VM running
- **`teardown` subcommand:** kill QEMU, remove overlay, PID file, and keys
- **Signal handler (SIGINT/SIGTERM):** clean teardown on Ctrl-C

## Host Safety

Running commands against `localhost` with port forwarding is inherently risky — a wrong port could hit the Mac host.

Safeguards:

1. **Explicit ports everywhere.** A single config dict at the top of the script holds all port mappings. Every SSH/SCP invocation references it. No bare `ssh localhost` anywhere.
2. **`boxmunge init` gets the forwarded port.** The `.boxmunge` config points `stage`/`promote` at `localhost:19220`, not port 922 on the Mac.
3. **Pre-flight sanity check.** Before running server-setup, the script SSHes to the target on the forwarded port and checks `/etc/os-release` for Debian. If it sees macOS (or anything else), it aborts with a loud error.
4. **Ephemeral SSH key.** Generated per-run and only installed in the VM via cloud-init. Even if a command hit the Mac, auth would fail.

## The `--self-signed-tls` Flag

A small addition to the production code to support testing without real DNS or Let's Encrypt.

### `init-host.sh`

- New optional flag `--self-signed-tls`
- When set, the Caddyfile template emits `tls internal` instead of the default ACME auto-TLS
- No other changes — directory layout, Docker config, reverse proxy routing all identical

### `boxmunge server-setup` CLI

- New flag `--self-signed-tls` passed through to `init-host.sh`
- Boolean flag, no validation needed

### Caddy behaviour

- `tls internal` makes Caddy generate a self-signed cert from its own internal CA
- HTTPS works, clients use `-k` / `--insecure` to accept it
- No ACME, no outbound requests, no DNS dependency

Also useful outside testing — LAN setups, servers behind a load balancer that terminates TLS.

## Canary Project

The existing `canary/` project gets a small stateful HTTP service for end-to-end verification.

### Service design

A tiny Python `http.server`-based app (no dependencies) with three endpoints:

- `GET /version` — returns the build-time version flag (baked in via a `VERSION` file copied into the image)
- `POST /data` — writes the request body to a file on a Docker volume
- `GET /data` — reads the file back

### Files added/modified in `canary/`

- `app/server.py` — the HTTP service (~30 lines)
- `app/Dockerfile` — builds from python:3-slim, copies server.py and VERSION
- `VERSION` — text file with the version string, modified by the test script before each build
- `compose.yml` — updated with the new service and a named volume
- `manifest.yml` — updated to register the service
- `boxmunge-scripts/smoke.sh` — updated to curl `/version` for a 200

### Why this design

- No database, no framework — file read/write on a mounted volume
- The volume is what boxmunge backs up and restores
- The image builds from the canary directory, so it flows through the normal `stage`/`promote` pipeline — no registry pulls
- The version flag is baked at build time, so restoring a backup also restores the old image version

## Test Sequence

Six phases. Each phase prints a header, each step prints PASS/FAIL. On any failure, the script stops immediately and enters the failure path.

### Phase 1 — Server setup

1. Run `boxmunge server-setup test@localhost -p 12222 --email test@example.com --ssh-key .cache/vm/test_key.pub --self-signed-tls`
2. Assert exit code 0
3. SSH in as `supervisor` on port 19220 and verify:
   - `/opt/boxmunge/config/boxmunge.yml` exists
   - Docker is running (`docker info`)
   - Caddy container is up (`docker ps`)
   - `deploy` and `supervisor` users exist

### Phase 2 — Deploy v1

4. Copy canary project to a temp dir, write `v1` to `VERSION`
5. Run `boxmunge init --server localhost --port 19220 --project canary`
6. Run `boxmunge stage`
7. Verify staging: `curl -k https://localhost:18443/ -H "Host: staging.<hostname>"` returns 200
8. SSH in, verify staging containers running
9. Run `boxmunge promote`
10. Verify production: `curl -k https://localhost:18443/ -H "Host: <hostname>"` returns 200
11. SSH in, verify production containers running, staging containers gone

### Phase 3 — Stateful write (v1)

12. `POST /data` with body `"alpha"` via curl (with `Host:` header, `-k`)
13. `GET /data` → assert response is `"alpha"`
14. `GET /version` → assert response is `"v1"`

### Phase 4 — Backup

15. SSH as supervisor: run backup command for canary project
16. Verify backup file exists on the server

### Phase 5 — Deploy v2 and overwrite

17. Update `VERSION` to `v2` in canary temp dir
18. Run `boxmunge stage` → `boxmunge promote` (redeploy with v2)
19. `GET /version` → assert `"v2"`
20. `POST /data` with body `"bravo"`
21. `GET /data` → assert `"bravo"`

### Phase 6 — Restore and verify rollback

22. SSH as supervisor: restore from the backup taken in phase 4 (restores data volume and project state)
23. Re-deploy via `boxmunge prod-deploy` to bring up containers from the restored state
24. `GET /version` → assert `"v1"` (restored image)
25. `GET /data` → assert `"alpha"` (restored data, not `"bravo"`)

### Cleanup

26. On success: kill VM, remove overlay, print summary with total time
27. On failure: print which phase/step failed, expected vs actual, SSH command to connect

## Exit Codes

- `0` — all phases passed
- `1` — a test phase failed
- `2` — infrastructure failure (QEMU wouldn't start, image download failed, SSH never came up)

## CI Integration

**Now:** Manual via `make test-vm`. The script is headless, non-interactive (except for the `server-setup` confirmation prompt, which the test will need to handle — either `--yes` flag or piped `echo y`).

**Future:** GitHub Actions `workflow_dispatch` or pre-release gate. Requires a runner with KVM support (self-hosted or a CI service like Buildjet/Namespace). Standard GitHub runners lack KVM. No changes to the script needed — it already uses exit codes and structured output.

## Dependencies

- QEMU (`brew install qemu` — already installed)
- Python 3.x (already present)
- `hdiutil` (macOS built-in, for cloud-init ISO)
- `ssh`, `scp`, `curl` (macOS built-in)
- No pip packages — stdlib only

## Production Code Changes

Two small additions to the CLI and bootstrap script, both useful beyond testing:

### `--self-signed-tls` flag

- Added to `init-host.sh` and `boxmunge server-setup`
- Switches Caddy from ACME auto-TLS to `tls internal` (self-signed)
- Use case: testing, LAN deployments, servers behind TLS-terminating load balancers

### `--yes` / `-y` flag on `server-setup`

- Skips the interactive "Are you sure? [y/N]" confirmation
- Standard pattern for CLI tools used in automation
- Required for the test script to run non-interactively
