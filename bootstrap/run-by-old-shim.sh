#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/run-by-old-shim.sh — print 1 when install.sh is being run by an
# upgrade shim from 0.7.0 to 0.10.0, 0 otherwise. Run by install.sh.
#
# Those shims run install.sh between installing the new release into the
# standby slot and swapping to it, as later ones do, but without
# --upgrade-shim. Taken for a run by hand, install.sh would install the new
# release into env-active, still the previous release and the only rollback
# target, and record the new version before the swap. Each of them holds the
# legacy upgrade lock, upgrade-state/upgrade.lock, on descriptor 9
# (`exec 9>"$LOCK_FILE"; flock -n 9`), which install.sh, its child, inherits.
# So the test is: descriptor 9 here is that file (a regular file, not reached
# through a link); a fresh open of it cannot take the lock, so someone holds
# it; and flock on descriptor 9 itself succeeds, so the holder is this
# process's own open of it, which it shares with the shim that made it. A run
# by hand cannot pass: sudo closes inherited descriptors, and a descriptor 9
# opened on the lock by anything else is a different open, which an upgrade or
# health check holding the lock alongside blocks.
set -euo pipefail

BOXMUNGE_ROOT="${BOXMUNGE_ROOT:-/opt/boxmunge}"
exec python3 -I - "$BOXMUNGE_ROOT/upgrade-state/upgrade.lock" <<'PY'
import fcntl, os, stat, sys

lock = sys.argv[1]
try:
    inherited, named = os.fstat(9), os.lstat(lock)
except OSError:
    print(0)
    sys.exit(0)
if not stat.S_ISREG(named.st_mode) or (inherited.st_dev, inherited.st_ino) != (named.st_dev, named.st_ino):
    print(0)
    sys.exit(0)
try:
    fd = os.open(lock, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
except OSError as e:
    sys.exit(f"ERROR: run-by-old-shim.sh: descriptor 9 is {lock}, which cannot be opened: {e.strerror}")
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    pass
else:
    print(0)  # nobody holds it: not a shim mid-upgrade
    sys.exit(0)
try:
    # Succeeds only on the open that holds the lock; it is not released here
    # (the shim's descriptor keeps it after this process exits).
    fcntl.flock(9, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    print(0)  # someone else holds it, on an open that is not this one
else:
    print(1)
PY
