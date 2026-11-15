#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/jobs-dirs.sh: make the job queue's directories and the jobs gate,
# deploy's, before the units are installed (boxmunge-jobs.path watches
# state/jobs/queue/ and the runner and its workers run as deploy). Run by
# install.sh as root, on every install and upgrade; idempotent.
#
#   state/jobs/            deploy:deploy 0750
#   state/jobs/queue/      deploy:deploy 0750
#   state/jobs/gate.lock   deploy:deploy 0660, made O_EXCL and never replaced:
#                          running jobs and the upgrade shim flock it
#
# The same as the upgrade shim's open_lock_and_reexec makes jobs/ and the
# gate (scripts/boxmunge-upgrade.d/locks.sh); keep the two in step. state/ is
# deploy-writable, so nothing is followed if a link: each name is opened
# under its parent's descriptor, and owner and mode are set through the
# descriptor. One that exists is given its mode; one that is not the right
# kind of file, or not deploy's, fails the install, naming it.
set -euo pipefail

BOXMUNGE_ROOT="${BOXMUNGE_ROOT:-/opt/boxmunge}"
DEPLOY_USER="${DEPLOY_USER:-deploy}"
DEPLOY_GROUP="${DEPLOY_GROUP:-deploy}"

python3 -I - "${BOXMUNGE_ROOT}/state" "${DEPLOY_USER}" "${DEPLOY_GROUP}" <<'PY'
import errno, grp, os, pwd, stat, sys

state, user, group = sys.argv[1:]
uid, gid = pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def fatal(path, what):
    sys.exit(f"ERROR: {path} {what}; refusing to use it as root. Remove it and run the "
             f"install again.")


def refused(path, e, kind):
    planted = e.errno in (errno.ELOOP, errno.ENOTDIR, errno.ENXIO, errno.EOPNOTSUPP)
    fatal(path, f"is a symlink or not {kind}" if planted else f"cannot be opened ({e.strerror})")


def own(path, fd, mode, created):
    st = os.fstat(fd)
    if not created and st.st_uid != uid:
        fatal(path, f"is owned by uid {st.st_uid}, not {user}")
    os.fchown(fd, uid, gid)
    os.fchmod(fd, mode)


def directory(parent_fd, name, path):
    created = False
    try:
        fd = os.open(name, DIRECTORY, dir_fd=parent_fd)
    except FileNotFoundError:
        try:
            os.mkdir(name, 0o750, dir_fd=parent_fd)
            created = True
        except FileExistsError:
            pass
        try:
            fd = os.open(name, DIRECTORY, dir_fd=parent_fd)
        except OSError as e:
            refused(path, e, "a directory")
        # Between the mkdir and the open, deploy could rename another
        # directory in: only the empty one made here is given away.
        if created and (os.fstat(fd).st_uid != os.geteuid() or os.listdir(fd)):
            fatal(path, "was replaced while being made")
    except OSError as e:
        refused(path, e, "a directory")
    own(path, fd, 0o750, created)
    print(f"  {path}: {'made' if created else 'present'}, {user}:{group} 0750")
    return fd


def gate(parent_fd, path):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    created = False
    try:
        fd = os.open("gate.lock", flags | os.O_CREAT | os.O_EXCL, 0o660, dir_fd=parent_fd)
        created = True
    except FileExistsError:
        try:
            fd = os.open("gate.lock", flags, dir_fd=parent_fd)
        except OSError as e:
            refused(path, e, "a regular file")
    except OSError as e:
        refused(path, e, "a regular file")
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        fatal(path, "is not a plain regular file")
    own(path, fd, 0o660, created)
    print(f"  {path}: {'made' if created else 'present'}, {user}:{group} 0660")
    os.close(fd)


try:
    state_fd = os.open(state, DIRECTORY)
except OSError as e:
    refused(state, e, "a directory")
jobs_fd = directory(state_fd, "jobs", f"{state}/jobs")
os.close(directory(jobs_fd, "queue", f"{state}/jobs/queue"))
gate(jobs_fd, f"{state}/jobs/gate.lock")
PY
