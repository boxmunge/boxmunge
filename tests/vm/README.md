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
