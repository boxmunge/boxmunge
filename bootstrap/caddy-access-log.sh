#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/caddy-access-log.sh — move an existing box's Caddy access log from
# a file to stdout. Run by install.sh on every install and upgrade; idempotent.
#
#   sites    before Caddy is recreated: rewrite the generated log block in
#            caddy/sites, refuse any config that still names /var/log/caddy
#   retire   once Caddy runs without the mount: remove caddy/logs
#
# Earlier releases wrote every site's access log to /var/log/caddy/access.log,
# a bind mount of caddy/logs that the host's CrowdSec read as root. Under user-
# ID remapping Caddy owns that directory, so it decides what root opens there (a
# FIFO, /dev/zero, a link to a root-only file). Caddy now logs to stdout and
# CrowdSec reads it through Docker (crowdsec-acquis.sh). caddy/compose.yml no
# longer mounts /var/log/caddy and Caddy's root filesystem is read-only, so a
# site config still naming it would stop Caddy from starting.
set -euo pipefail
# install.sh runs from the installer's root-only (0700) extraction dir, which
# a command run as deploy cannot start from.
cd /

BOXMUNGE_ROOT="${BOXMUNGE_ROOT:-/opt/boxmunge}"
DEPLOY_USER="${DEPLOY_USER:-deploy}"
SITES="${BOXMUNGE_ROOT}/caddy/sites"
JOURNAL="${BOXMUNGE_ROOT}/caddy/.site-journal"

# Swaps the log block caddy.py generated before for the one it generates now,
# in every regular *.conf in caddy/sites and in the texts of pending
# caddy_journal entries (a failed validation would otherwise restore the old
# block). Links, FIFOs and other non-regular files are skipped, never opened
# for reading. NEW must equal caddy.py's _access_log_lines (a test checks).
REWRITE="$(cat <<'PY'
import json, os, stat, sys, tempfile

OLD = """    log {
        output file /var/log/caddy/access.log {
            roll_size 50MiB
            roll_keep 5
        }
        format json
    }
"""
NEW = """    log_append user_agent {http.request.header.User-Agent}
    log {
        output stdout
        format filter {
            wrap json
            fields {
                request>headers delete
                request>tls delete
                resp_headers delete
                request>uri regexp "^(.{1000}.{1000}.{48}).+$" "${1}"
                request>host regexp "^(.{256}).+$" "${1}"
                request>method regexp "^(.{32}).+$" "${1}"
                user_agent regexp "^(.{512}).+$" "${1}"
                user_id regexp "^(.{256}).+$" "${1}"
            }
        }
    }
"""


def rewrite(path, edit):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return  # a link (ELOOP) or gone: not a file boxmunge wrote
    with os.fdopen(fd) as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode):
            return
        text = f.read()
    changed = edit(text)
    if changed == text:
        return
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".boxmunge-rewrite-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(changed)
        os.chmod(tmp, stat.S_IMODE(st.st_mode))
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def entry(text):
    record = json.loads(text)
    for key in ("previous", "written"):
        if isinstance(record.get(key), str):
            record[key] = record[key].replace(OLD, NEW)
    return json.dumps(record)


sites, journal = sys.argv[1:]
for name in sorted(os.listdir(sites)):
    if name.endswith(".conf"):
        rewrite(os.path.join(sites, name), lambda text: text.replace(OLD, NEW))
if os.path.isdir(journal):
    for name in sorted(os.listdir(journal)):
        if name.endswith(".json"):
            rewrite(os.path.join(journal, name), entry)
PY
)"

# As the deploy user, who writes these files on every deploy anyway: nothing
# deploy planted there is ever opened as root.
as_deploy() { runuser -u "${DEPLOY_USER}" -- "$@"; }

sites() {
    [[ -d "${SITES}" ]] || return 0
    as_deploy python3 -I -c "${REWRITE}" "${SITES}" "${JOURNAL}"
    local targets=("${SITES}") left status=0
    if [[ -d "${JOURNAL}" ]]; then
        targets+=("${JOURNAL}")
    fi
    shopt -s nullglob
    targets+=("${BOXMUNGE_ROOT}"/projects/*/caddy.override.conf)
    shopt -u nullglob
    left="$(as_deploy grep -rlF --devices=skip /var/log/caddy "${targets[@]}")" || status=$?
    if [[ ${status} -eq 1 ]]; then
        return 0
    fi
    if [[ ${status} -eq 0 ]]; then
        echo "ERROR: these Caddy configs still write an access log under /var/log/caddy," >&2
        echo "       which Caddy no longer mounts, so Caddy could not start:" >&2
        sed 's/^/         /' <<<"${left}" >&2
        echo "       Replace each log block with the one boxmunge generates (CrowdSec" >&2
        echo "       reads Caddy's stdout; see OPERATIONS.md, 'Caddy access log'), then run" >&2
        echo "       the install or upgrade again (after 'boxmunge-upgrade clear-blocklist" >&2
        echo "       <version>' if an upgrade stopped here)." >&2
    else
        echo "ERROR: could not check ${targets[*]} for" >&2
        echo "       /var/log/caddy (grep exit ${status}); fix what grep reported above." >&2
    fi
    exit 1
}

# rm never follows a link inside the directory Caddy wrote to.
retire() {
    if [[ -e "${BOXMUNGE_ROOT}/caddy/logs" ]]; then
        rm -rf --one-file-system -- "${BOXMUNGE_ROOT}/caddy/logs"
        echo "  Removed caddy/logs: Caddy's access log is on its stdout now"
    fi
}

case "${1:-}" in
    sites) sites ;;
    retire) retire ;;
    *) echo "usage: $0 sites|retire" >&2; exit 2 ;;
esac
