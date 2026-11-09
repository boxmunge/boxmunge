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
# through a link), and a fresh open of it cannot take the lock, because the
# shim's open holds it. A run by hand cannot pass it: sudo closes inherited
# descriptors, and an upgrade or health check running alongside holds the lock
# on a descriptor of its own, not on this process's 9.
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
    print(1)
else:
    # Open on the lock but not holding it: not a shim mid-upgrade.
    print(0)
PY
