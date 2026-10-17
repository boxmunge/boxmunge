# shellcheck shell=bash
# state.sh — validation of everything the shim reads, the active slot, the
# lock, the blocklist, per-version failure counts, and the upgrade policy.
# Part of boxmunge-upgrade (runs as root); scripts/build-shim.py inlines it into
# the shim that releases ship.

# ---------------------------------------------------------------------------
# Deploy-writable state.
#
# upgrade-state/ is root:deploy 0770 so the deploy shell can end probation
# early. Everything read from it is therefore untrusted input to this root
# process. Each value is checked against a strict allowlist before it can
# reach an executable path, a URL, or an rm -rf, and anything else stops the
# shim. Symlinks are refused, every read opens without following a link or
# blocking on a FIFO (read_untrusted), and writes go through rename(2), so a
# planted link is replaced rather than followed.
# ---------------------------------------------------------------------------
SEMVER_RE='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
ACTIVE_SLOT=""
LOCK_HELD=0

printable() { local s="${1:0:80}"; printf '%s' "${s//[^[:alnum:]._+-]/?}"; }

require_slot() {  # require_slot <value> <where>
    [[ "$1" == "a" || "$1" == "b" ]] \
        || die "Invalid slot '$(printable "$1")' in $2 (expected a or b); refusing to continue"
}

require_semver() {  # require_semver <value> <where>
    [[ "$1" =~ $SEMVER_RE ]] \
        || die "Invalid version '$(printable "$1")' in $2 (expected semver like 0.3.5 or 0.3.5-rc.1)"
}

refuse_symlink() {
    [[ ! -L "$1" ]] || die "$1 is a symlink; refusing to use it as root. Remove it and re-run."
}

# read_untrusted <file>: print a deploy-writable file. A FIFO would block a
# plain read forever with upgrade.lock held, and a link swapped in after
# refuse_symlink would be read through, so the file is opened O_NOFOLLOW |
# O_NONBLOCK and anything but a regular file is refused. Use it as
# value="$(read_untrusted <file>)" || exit 1 (it has already said why).
read_untrusted() {
    local rc=0
    python3 - "$1" <<'PYRU' || rc=$?
import errno, os, stat, sys
try:
    fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
except OSError as e:
    sys.exit(3 if e.errno == errno.ELOOP else f"{sys.argv[1]}: {e.strerror}")
with os.fdopen(fd, "rb") as f:
    if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
        sys.exit(3)
    sys.stdout.buffer.write(f.read())
PYRU
    case "$rc" in
        0) ;;
        3) die "$1 is a symlink, FIFO or other non-regular file; refusing to read it as root. Remove it and re-run." ;;
        *) die "Cannot read $1; inspect it and repair or remove it" ;;
    esac
}

# replace_file <src> <dest>: rename(2), which never follows a link at <dest>.
# (GNU mv would move <src> INTO <dest> if <dest> were a link to a directory.)
replace_file() {
    python3 -c 'import os, sys; os.replace(sys.argv[1], sys.argv[2])' "$1" "$2"
}

# load_active_slot: set ACTIVE_SLOT from the root-owned env-active symlink and
# the deploy-writable active-slot file. Both must name a or b, and they must
# agree: a forged active-slot would otherwise make the live venv look like
# the standby, and the next upgrade would rm -rf it. The one exception is a
# crash inside swap_to, proven by a root-owned upgrade-inflight or
# rollback-inflight marker in either slot (both are written before any swap):
# then root's env-active is the truth and active-slot is rewritten to match.
load_active_slot() {
    local from_file="" from_link="" target
    refuse_symlink "$ACTIVE_SLOT_FILE"
    if [[ -e "$ACTIVE_SLOT_FILE" ]]; then
        from_file="$(read_untrusted "$ACTIVE_SLOT_FILE")" || exit 1
        require_slot "$from_file" "$ACTIVE_SLOT_FILE"
    fi
    if [[ -L "$BOXMUNGE_ROOT/env-active" ]]; then
        target="$(readlink "$BOXMUNGE_ROOT/env-active")"
        case "$target" in
            "$BOXMUNGE_ROOT/env-a") from_link="a" ;;
            "$BOXMUNGE_ROOT/env-b") from_link="b" ;;
            *) die "env-active points at '$(printable "$target")', not env-a or env-b" ;;
        esac
    fi
    if [[ -n "$from_file" && -n "$from_link" && "$from_file" != "$from_link" ]]; then
        [[ -e "$(inflight_marker a)" || -e "$(inflight_marker b)" || -e "$(rollback_marker a)" || -e "$(rollback_marker b)" ]] \
            || die "active-slot says '$from_file' but env-active points at env-$from_link; refusing to guess which venv is live"
        log "WARN: active-slot disagrees with env-active after an interrupted swap; following env-active (slot $from_link)"
        write_active_slot_file "$from_link"
    fi
    ACTIVE_SLOT="${from_link:-$from_file}"
    [[ -n "$ACTIVE_SLOT" ]] || die "No active slot: neither $ACTIVE_SLOT_FILE nor $BOXMUNGE_ROOT/env-active exists"
}

standby_slot() { [[ "$ACTIVE_SLOT" == "a" ]] && echo "b" || echo "a"; }
active_venv() { echo "$BOXMUNGE_ROOT/env-$ACTIVE_SLOT"; }

# acquire_lock [skip]: take upgrade.lock once per run. With "skip", a busy
# lock exits 0 (the health timer retries on its next fire); otherwise it dies.
#
# Deploy can plant anything at upgrade.lock, and swap it between any check
# and the open. Every bash redirection follows a link, and the writing ones
# create a missing target, so bash never opens it: open_lock_and_reexec has
# Python open it without following a link or blocking on a FIFO, refuse
# anything but a plain regular file, put it on fd 9 and run this shim again
# with the same arguments. That run finds BM_UPGRADE_LOCK_FD=9 and checks fd
# 9 is upgrade.lock itself before it takes the flock.
acquire_lock() {
    [[ "$LOCK_HELD" -eq 1 ]] && return 0
    if [[ "${BM_UPGRADE_LOCK_FD:-}" != 9 ]]; then
        mkdir -p "$STATE_DIR"
        refuse_symlink "$LOCK_FILE"
        open_lock_and_reexec
    fi
    unset BM_UPGRADE_LOCK_FD  # children inherit fd 9, never the claim that it is checked
    python3 -c 'import os, stat, sys
fd, name = os.fstat(9), os.lstat(sys.argv[1])
sys.exit(not (stat.S_ISREG(fd.st_mode) and (fd.st_dev, fd.st_ino) == (name.st_dev, name.st_ino)))' \
        "$LOCK_FILE" 2>/dev/null \
        || die "fd 9 is not $LOCK_FILE (it was replaced, or the descriptor came from elsewhere); refusing to lock it. Remove it and re-run."
    if ! flock -n 9; then
        [[ "${1:-}" == "skip" ]] && { log "Another upgrade is in progress; skipping"; exit 0; }
        die "Another upgrade is in progress"
    fi
    LOCK_HELD=1
}

# open_lock_and_reexec: see acquire_lock. Replaces this process; prints a
# FATAL line like die() when upgrade.lock cannot be used.
open_lock_and_reexec() {
    exec python3 -c '
import errno, os, stat, sys, time
path, shell, shim, args = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]

def fatal(what):
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    sys.exit(f"{now} boxmunge-upgrade: FATAL: {path} {what}; refusing to use it as root. Remove it and re-run.")

try:
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
except OSError as e:
    fatal("is a symlink" if e.errno == errno.ELOOP else f"cannot be opened ({e.strerror})")
st = os.fstat(fd)
if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
    fatal("is not a plain regular file")
os.set_blocking(fd, True)
if fd != 9:
    os.dup2(fd, 9)
    os.close(fd)
os.set_inheritable(9, True)
os.environ["BM_UPGRADE_LOCK_FD"] = "9"
os.execv(shell, [shell, shim, *args])
' "$LOCK_FILE" "$BASH" "$SHIM_PATH" "${SHIM_ARGS[@]+"${SHIM_ARGS[@]}"}"
}

# is_blocklisted <version>: 0 if listed, 1 if not. A blocklist that is not a
# JSON object keyed by semver strings is corrupt or tampered with: stop.
is_blocklisted() {
    local rc=0 content
    refuse_symlink "$BLOCKLIST_FILE"
    [[ -e "$BLOCKLIST_FILE" ]] || return 1
    content="$(read_untrusted "$BLOCKLIST_FILE")" || exit 1
    BM_VERSION="$1" BM_BLOCKLIST="$content" BM_SEMVER_RE="$SEMVER_RE" python3 - <<'PYBL' || rc=$?
import json, os, re, sys
try:
    bl = json.loads(os.environ["BM_BLOCKLIST"])
except ValueError as e:
    print(f"blocklist unreadable: {e}", file=sys.stderr)
    sys.exit(3)
pattern = re.compile(os.environ["BM_SEMVER_RE"])
if not isinstance(bl, dict) or not all(isinstance(k, str) and pattern.fullmatch(k) for k in bl):
    print("blocklist is not an object keyed by semver versions", file=sys.stderr)
    sys.exit(3)
sys.exit(0 if os.environ["BM_VERSION"] in bl else 1)
PYBL
    case "$rc" in
        0|1) return "$rc" ;;
        *) die "$BLOCKLIST_FILE is malformed; inspect it and repair or remove it" ;;
    esac
}

# write_active_slot_file <slot>: the temp file is written, chmod'd and synced
# through the descriptor that created it. upgrade-state/ is deploy-writable,
# so reopening the temp by name could follow a link deploy renamed over it.
write_active_slot_file() {
    BM_SLOT="$1" BM_FILE="$ACTIVE_SLOT_FILE" python3 - <<'PYAS'
import os, tempfile
path = os.environ["BM_FILE"]
directory = os.path.dirname(path)
fd, tmp = tempfile.mkstemp(dir=directory, prefix=".active-slot.")
try:
    with os.fdopen(fd, "w") as f:
        f.write(os.environ["BM_SLOT"] + "\n")
        f.flush()
        os.fchmod(f.fileno(), 0o644)
        os.fsync(f.fileno())
    os.replace(tmp, path)
except BaseException:
    if os.path.lexists(tmp):
        os.unlink(tmp)
    raise
dir_fd = os.open(directory, os.O_RDONLY)
os.fsync(dir_fd)
os.close(dir_fd)
PYAS
}

add_blocklist() {
    local version="$1" reason="$2"
    BM_VERSION="$version" BM_REASON="$reason" "$(active_venv)/bin/python" -c "
import os
from boxmunge.upgrade_state import add_to_blocklist
from boxmunge.paths import BoxPaths
add_to_blocklist(BoxPaths(), os.environ['BM_VERSION'], os.environ['BM_REASON'])
"
}

# Failures that are rarely the release's fault are counted per version, so
# the first one is retried and only a repeat blocklists:
#   interruptions <version> [<count>]  the upgrade was interrupted after its
#                                      venv swap (a power cut, a kill)
#   pip_failures <version> [<count>]   its hash-pinned dependencies failed to
#                                      install (a network blip, a full disk)
# Each prints the count, or sets it (0 forgets it).
interruptions() { failure_count "$INTERRUPTED_FILE" "$@"; }
pip_failures() { failure_count "$PIP_FAILURES_FILE" "$@"; }

# failure_count <file> <version> [<count>]: the counts behind the above. Kept
# in a root-only directory, not deploy-writable upgrade-state/, so deploy
# cannot wedge recovery with a malformed file. Written by fsync + rename +
# directory fsync.
failure_count() {
    local file="$1"
    shift
    refuse_symlink "$UPGRADE_ROOT_DIR"
    refuse_symlink "$file"
    [[ $# -eq 1 || -d "$UPGRADE_ROOT_DIR" ]] || mkdir -m 0700 "$UPGRADE_ROOT_DIR"
    BM_VERSION="$1" BM_COUNT="${2:-}" BM_FILE="$file" BM_SEMVER_RE="$SEMVER_RE" python3 - <<'PYINT' \
        || die "$file is malformed; inspect it and repair or remove it"
import json, os, re, sys, tempfile
path, version, count = os.environ["BM_FILE"], os.environ["BM_VERSION"], os.environ["BM_COUNT"]
counts = {}
if os.path.exists(path):
    with open(path) as f:
        counts = json.load(f)
pattern = re.compile(os.environ["BM_SEMVER_RE"])
if not isinstance(counts, dict) or not all(
        isinstance(k, str) and pattern.fullmatch(k) and type(v) is int for k, v in counts.items()):
    sys.exit(f"{os.path.basename(path)} is not an object of semver version -> count")
if not count:
    print(counts.get(version, 0))
    sys.exit(0)
counts.pop(version, None)
if int(count):
    counts[version] = int(count)
directory = os.path.dirname(path)
fd, tmp = tempfile.mkstemp(dir=directory, prefix=f".{os.path.basename(path)}.")
with os.fdopen(fd, "w") as f:
    json.dump(counts, f)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, path)
dir_fd = os.open(directory, os.O_RDONLY)
os.fsync(dir_fd)
os.close(dir_fd)
PYINT
}

# ---------------------------------------------------------------------------
# Upgrade policy: what each entry point may install.
# ---------------------------------------------------------------------------

# semver_lt <a> <b>: true when <a> has lower semver precedence than <b>.
semver_lt() {
    BM_A="$1" BM_B="$2" python3 - <<'PYSV'
import os, sys
def key(v):
    core, _, pre = v.partition("-")
    nums = tuple(int(x) for x in core.split("."))
    if not pre:
        return nums, 1, ()
    return nums, 0, tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
sys.exit(0 if key(os.environ["BM_A"]) < key(os.environ["BM_B"]) else 1)
PYSV
}

# installed_version: the semver recorded in config/version (root-owned; the
# config dir is not deploy-writable).
installed_version() {
    local v
    [[ -f "$VERSION_FILE" ]] || die "No installed version recorded at $VERSION_FILE"
    v="$(cat "$VERSION_FILE")"
    v="${v%%+*}"
    require_semver "$v" "$VERSION_FILE"
    echo "$v"
}

# check_policy <version> <mode>: mode is run (timer), target (deploy) or
# force (operator). Only force may install a blocklisted or older version,
# and no mode a release from before the hash-pinned MCP requirements. That
# refusal is about this shim, not the release, so it is never blocklisted.
check_policy() {
    local version="$1" mode="$2" installed operator_hint
    require_semver "$version" "requested version"
    if ! semver_lt "$LAST_RELEASE_WITHOUT_MCP_LOCK" "$version"; then
        die "Bundle $version predates the hash-pinned requirements-mcp.txt every install needs; force-target cannot go below the first release after $LAST_RELEASE_WITHOUT_MCP_LOCK"
    fi
    operator_hint="To override, run as supervisor: sudo $BIN_DIR/boxmunge-upgrade force-target $version"
    if [[ "$mode" == "force" ]]; then
        log "WARN: operator override: blocklist and downgrade floor not enforced for $version"
        return 0
    fi
    if is_blocklisted "$version"; then
        if [[ "$mode" == "run" ]]; then
            log "Version $version is blocklisted, skipping"
            exit 0
        fi
        die "Version $version is blocklisted on this box (it failed an earlier upgrade). $operator_hint"
    fi
    installed="$(installed_version)"
    if semver_lt "$version" "$installed"; then
        die "Refusing to downgrade from $installed to $version. $operator_hint"
    fi
}
