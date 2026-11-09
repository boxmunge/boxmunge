#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/upgrade-state-perms.sh — give each upgrade-state file the deploy
# user reads group deploy and mode 0660. Run by install.sh as root on every
# install and upgrade; idempotent.
#
# deploy reads active-slot and blocklist.json, and reads probation.json to end
# a probation early. Re-owning the whole directory instead (chown -R) left
# probation.json root:deploy 0600, so every deploy, rollback, restore and
# backup during probation crashed on it (#107). Owners are left as they are.
#
# upgrade-state/ is deploy-writable, so deploy may have put a link or a FIFO
# at any of these names: each file is opened without following a link or
# blocking, and only a plain regular file is changed, through its descriptor.
set -euo pipefail

BOXMUNGE_ROOT="${BOXMUNGE_ROOT:-/opt/boxmunge}"
DEPLOY_GROUP="${DEPLOY_GROUP:-deploy}"

python3 -I - "${BOXMUNGE_ROOT}/upgrade-state" "${DEPLOY_GROUP}" <<'PY'
import errno, grp, os, stat, sys

state, group = sys.argv[1:]
gid = grp.getgrnam(group).gr_gid
dir_fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
for name in ("active-slot", "blocklist.json", "probation.json"):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    except FileNotFoundError:
        continue
    except OSError as e:
        if e.errno != errno.ELOOP:
            raise
        print(f"  {state}/{name} is not a plain regular file; left as is", file=sys.stderr)
        continue
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            print(f"  {state}/{name} is not a plain regular file; left as is", file=sys.stderr)
            continue
        os.fchown(fd, -1, gid)
        os.fchmod(fd, 0o660)
    finally:
        os.close(fd)
PY
