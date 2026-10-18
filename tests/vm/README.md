# VM Integration Tests

Full-stack acceptance test that boots a fresh Debian 13 VM and exercises
the entire boxmunge workflow: server-setup, deploy, promote, backup,
and restore with data integrity verification.

## Prerequisites

- QEMU (`brew install qemu`)
- `mkisofs` (`brew install cdrtools`) — for building cloud-init ISO
- Python 3.x
- The `boxmunge` CLI installed (`pip install -e ./cli`)
- ~1GB disk for the cached Debian cloud image
- Outbound network for `qemu-system-x86_64`. With QEMU user-mode networking
  every guest connection, DNS included, is made by the qemu process on the
  host, so an application firewall (Little Snitch, LuLu) that blocks it leaves
  the guest with "no DNS", or reaching some hosts and not others. Homebrew's
  qemu is ad-hoc signed: an allow rule stops matching after `brew upgrade
  qemu`. Right after boot the tests probe every host the install reaches
  (Debian and Docker packages, GitHub and its release-asset host, Docker Hub
  and its layer store, Alpine's CDN) and stop with this explanation, listing
  each host that failed.

## Host key

The harness generates the VM's ed25519 host key for each run, installs it
through cloud-init, and records it in `~/.ssh/known_hosts` for
`[localhost]:12222` and `[localhost]:19220` before the VM boots. server-setup
finds the key there, so it never runs `ssh-keyscan` (Debian 13's sshd
penalises keyscan's unauthenticated connections under PerSourcePenalties, so
repeated runs get empty scans), and the harness's own SSH checks the key
strictly. The private key is deleted once the cloud-init ISO is built; the
ISO (0600) and the known_hosts entries are removed by teardown. After boot
the test also requires `cloud-init status` to be clean, not degraded.

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
ssh -p 12222 test@localhost
ssh -p 19220 supervisor@localhost
```

Run `./tests/vm/vm-test.py teardown` when done.

## Other scenarios

- `tests/vm/vm-staging.py <scenario>` — a 0.10.1 box upgrading to this tree's
  build around a stage (`discard`, `keep-then-rollback`, `hotfix-during-stage`,
  `probation-rollback`).
- `tests/vm/vm-userns.py docker29|docker28` — the user-namespace migration
  rehearsal: a 0.10.1 box (Docker 29 on the containerd store, or Docker 28 on
  overlay2) upgrades, does what `userns-migrate --check` asks, migrates while
  the host measures the downtime through Caddy, survives a kill -9 and a power
  cut in each phase, soaks, rolls back, migrates again and commits. It prints
  the measured figures (image MB, files shifted, downtime, bytes reclaimed)
  and writes them to `.cache/vm/vm-userns/results-<flavour>.json`.

Both take `teardown`, and leave the VM running on failure.

## First run

The first run downloads the Debian 13 cloud image (~700MB) and caches it
in `.cache/vm/`. Subsequent runs reuse the cached image via copy-on-write
overlays, so only the delta is stored per run.
