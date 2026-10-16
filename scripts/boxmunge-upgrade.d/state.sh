# shellcheck shell=bash
# state.sh — sourced by boxmunge-upgrade (root). Validation of everything
# the shim reads, the active slot, the lock, the blocklist, interruption
# counts, and the upgrade policy.
# Must match the shim's UPGRADE_LIB_API; the shim refuses to run otherwise.
# shellcheck disable=SC2034  # read by the shim's load_libs
BM_LIB_API=1

# ---------------------------------------------------------------------------
# Deploy-writable state.
#
# upgrade-state/ is root:deploy 0770 so the deploy shell can end probation
# early. Everything read from it is therefore untrusted input to this root
# process. Each value is checked against a strict allowlist before it can
# reach an executable path, a URL, or an rm -rf, and anything else stops the
# shim. Symlinks are refused, and writes go through rename(2), so a planted
# link is replaced rather than followed.
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
    [[ ! -L "$1" ]] || die "$1 is a symlink; refusing to use it as root"
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
# crash inside swap_to, proven by a root-owned upgrade-inflight marker: then
# root's env-active is the truth and active-slot is rewritten to match it.
load_active_slot() {
    local from_file="" from_link="" target
    refuse_symlink "$ACTIVE_SLOT_FILE"
    if [[ -f "$ACTIVE_SLOT_FILE" ]]; then
        from_file="$(cat "$ACTIVE_SLOT_FILE")"
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
        [[ -e "$(inflight_marker a)" || -e "$(inflight_marker b)" ]] \
            || die "active-slot says '$from_file' but env-active points at env-$from_link; refusing to guess which venv is live"
        log "WARN: active-slot disagrees with env-active after an interrupted upgrade; following env-active (slot $from_link)"
        write_active_slot_file "$from_link"
    fi
    ACTIVE_SLOT="${from_link:-$from_file}"
    [[ -n "$ACTIVE_SLOT" ]] || die "No active slot: neither $ACTIVE_SLOT_FILE nor $BOXMUNGE_ROOT/env-active exists"
}

standby_slot() { [[ "$ACTIVE_SLOT" == "a" ]] && echo "b" || echo "a"; }
active_venv() { echo "$BOXMUNGE_ROOT/env-$ACTIVE_SLOT"; }

# acquire_lock [skip]: take upgrade.lock once per run. With "skip", a busy
# lock exits 0 (the health timer retries on its next fire); otherwise it dies.
acquire_lock() {
    [[ "$LOCK_HELD" -eq 1 ]] && return 0
    mkdir -p "$STATE_DIR"
    refuse_symlink "$LOCK_FILE"
    exec 9>>"$LOCK_FILE"
    if ! flock -n 9; then
        [[ "${1:-}" == "skip" ]] && { log "Another upgrade is in progress; skipping"; exit 0; }
        die "Another upgrade is in progress"
    fi
    LOCK_HELD=1
}

# is_blocklisted <version>: 0 if listed, 1 if not. A blocklist that is not a
# JSON object keyed by semver strings is corrupt or tampered with: stop.
is_blocklisted() {
    local rc=0
    refuse_symlink "$BLOCKLIST_FILE"
    [[ -f "$BLOCKLIST_FILE" ]] || return 1
    BM_VERSION="$1" BM_BLOCKLIST="$BLOCKLIST_FILE" BM_SEMVER_RE="$SEMVER_RE" python3 - <<'PYBL' || rc=$?
import json, os, re, sys
try:
    with open(os.environ["BM_BLOCKLIST"]) as f:
        bl = json.load(f)
except (OSError, ValueError) as e:
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

write_active_slot_file() {
    local tmp
    tmp="$(mktemp "$STATE_DIR/.active-slot.XXXXXX")"
    echo "$1" > "$tmp"
    chmod 0644 "$tmp"
    replace_file "$tmp" "$ACTIVE_SLOT_FILE"
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

# interruptions <version> [<count>]: print how many times <version>'s upgrade
# was interrupted after its venv swap, or set that count (0 forgets it). Kept
# in a root-only directory, not deploy-writable upgrade-state/, so deploy
# cannot wedge recovery with a malformed file. Written by fsync + rename +
# directory fsync.
interruptions() {
    refuse_symlink "$UPGRADE_ROOT_DIR"
    refuse_symlink "$INTERRUPTED_FILE"
    [[ $# -eq 1 || -d "$UPGRADE_ROOT_DIR" ]] || mkdir -m 0700 "$UPGRADE_ROOT_DIR"
    BM_VERSION="$1" BM_COUNT="${2:-}" BM_FILE="$INTERRUPTED_FILE" BM_SEMVER_RE="$SEMVER_RE" python3 - <<'PYINT' \
        || die "$INTERRUPTED_FILE is malformed; inspect it and repair or remove it"
import json, os, re, sys, tempfile
path, version, count = os.environ["BM_FILE"], os.environ["BM_VERSION"], os.environ["BM_COUNT"]
counts = {}
if os.path.exists(path):
    with open(path) as f:
        counts = json.load(f)
pattern = re.compile(os.environ["BM_SEMVER_RE"])
if not isinstance(counts, dict) or not all(
        isinstance(k, str) and pattern.fullmatch(k) and type(v) is int for k, v in counts.items()):
    sys.exit("interrupted.json is not an object of semver version -> count")
if not count:
    print(counts.get(version, 0))
    sys.exit(0)
counts.pop(version, None)
if int(count):
    counts[version] = int(count)
directory = os.path.dirname(path)
fd, tmp = tempfile.mkstemp(dir=directory, prefix=".interrupted.")
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
# force (operator). Only force may install a blocklisted or older version.
check_policy() {
    local version="$1" mode="$2" installed operator_hint
    require_semver "$version" "requested version"
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
