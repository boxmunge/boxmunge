#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/caddy-log-path.sh: refuse to install over a box whose Caddy configs
# write a log under /var/log/caddy. Run by install.sh on an existing box,
# before it changes anything.
#
# Caddy's root filesystem is read-only and nothing is mounted at /var/log/caddy,
# so a config that writes a log there stops Caddy at config load: once Caddy is
# recreated, every site is down. Releases 0.11.0 to 0.11.6 mounted a tmpfs
# there, so a hand-written override or site file with such a log block
# validated and ran on them. This check is for that box. It goes when the
# upgrade floor reaches 0.11.7: from this release on a reload validates on the
# read-only root, so a box whose last install was 0.11.7 or later holds none.
#
# It reads what Caddy imports (caddy/sites/*.conf), the texts of pending site
# journal entries (a failed validation puts them back) and the project
# overrides. Only regular files, and as the deploy user, who writes them on
# every deploy: nothing deploy planted there is opened as root. Not all of
# caddy/sites, which may hold an operator's TLS key that deploy cannot read
# (#105). A check that cannot run is an error, not a pass.
set -euo pipefail
# install.sh runs from the installer's root-only (0700) extraction dir, which
# a command run as deploy cannot start from.
cd /

BOXMUNGE_ROOT="${BOXMUNGE_ROOT:-/opt/boxmunge}"
DEPLOY_USER="${DEPLOY_USER:-deploy}"
AGAIN="Then run the install or upgrade again. An upgrade that stopped here
       blocklisted its release, so clear that first:
       sudo ${BOXMUNGE_ROOT}/bin/boxmunge-upgrade clear-blocklist <that release>"

targets=()
shopt -s nullglob
for target in "${BOXMUNGE_ROOT}"/caddy/sites/*.conf "${BOXMUNGE_ROOT}"/caddy/.site-journal/*.json \
        "${BOXMUNGE_ROOT}"/projects/*/caddy.override.conf; do
    if [[ -f "${target}" && ! -L "${target}" ]]; then
        targets+=("${target}")
    fi
done
shopt -u nullglob
[[ ${#targets[@]} -gt 0 ]] || exit 0

status=0
found="$(runuser -u "${DEPLOY_USER}" -- grep -lF --devices=skip /var/log/caddy "${targets[@]}")" || status=$?
case "${status}" in
    1) exit 0 ;;
    0) echo "ERROR: these Caddy configs write a log under /var/log/caddy, which Caddy's" >&2
       echo "       container does not have from this release on. Caddy would not start" >&2
       echo "       on them, and every site would be down:" >&2
       while IFS= read -r file; do echo "         ${file}" >&2; done <<<"${found}"
       echo "       Nothing was changed. In each, remove that log block or make it" >&2
       echo "       \`output stdout\` (OPERATIONS.md, 'Caddy access log')." >&2
       echo "       ${AGAIN}" >&2 ;;
    *) echo "ERROR: could not check the Caddy configs for /var/log/caddy (grep exit" >&2
       echo "       ${status}). Nothing was changed. Fix what grep reported above." >&2
       echo "       ${AGAIN}" >&2 ;;
esac
exit 1
