#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/caddy-access-log.sh — move an existing box's Caddy access log from
# a file to stdout. Run by install.sh on every install and upgrade; idempotent.
#
#   sites    before Caddy is recreated: rewrite the generated file block in
#            caddy/sites, refuse any config that still names /var/log/caddy
#   retire   once Caddy runs without the mount: remove caddy/logs
#
# Earlier releases wrote every site's access log to /var/log/caddy/access.log,
# a bind mount of caddy/logs that the host's CrowdSec read as root. Under user-
# ID remapping Caddy owns that directory, so it decides what root opens there (a
# FIFO, /dev/zero, a link to a root-only file). Caddy now logs to stdout and
# CrowdSec reads it through Docker (crowdsec-caddy.sh). caddy/compose.yml no
# longer mounts /var/log/caddy and Caddy's root filesystem is read-only, so a
# site config still naming it would stop Caddy from starting.
set -euo pipefail

BOXMUNGE_ROOT="${BOXMUNGE_ROOT:-/opt/boxmunge}"
DEPLOY_USER="${DEPLOY_USER:-deploy}"
SITES="${BOXMUNGE_ROOT}/caddy/sites"

# The block caddy.py generated before, as it appears in a site file.
OLD_BLOCK='output file \/var\/log\/caddy\/access\.log \{\n {12}roll_size 50MiB\n {12}roll_keep 5\n {8}\}\n'

# As the deploy user, who writes these files on every deploy anyway: a link
# deploy planted in caddy/sites is skipped by find, never followed by root.
as_deploy() { runuser -u "${DEPLOY_USER}" -- "$@"; }

sites() {
    [[ -d "${SITES}" ]] || return 0
    as_deploy find "${SITES}" -maxdepth 1 -type f -name '*.conf' \
        -exec perl -0777 -i -pe "s/${OLD_BLOCK}/output stdout\\n/g" {} +
    local overrides=() left status=0
    shopt -s nullglob
    overrides=("${BOXMUNGE_ROOT}"/projects/*/caddy.override.conf)
    shopt -u nullglob
    left="$(as_deploy grep -rlF --devices=skip /var/log/caddy "${SITES}" "${overrides[@]}")" \
        || status=$?
    if [[ ${status} -eq 1 ]]; then
        return 0
    fi
    if [[ ${status} -eq 0 ]]; then
        echo "ERROR: these Caddy configs still write an access log under /var/log/caddy," >&2
        echo "       which Caddy no longer mounts, so Caddy could not start:" >&2
        sed 's/^/         /' <<<"${left}" >&2
        echo "       Change each log block's output to 'output stdout' (CrowdSec reads" >&2
        echo "       Caddy's stdout; see OPERATIONS.md, 'Caddy access log'), then run" >&2
        echo "       the install or upgrade again (after 'boxmunge-upgrade clear-blocklist" >&2
        echo "       <version>' if an upgrade stopped here)." >&2
    else
        echo "ERROR: could not check ${SITES} and the caddy.override.conf files for" >&2
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
