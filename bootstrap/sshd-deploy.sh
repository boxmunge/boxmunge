#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/sshd-deploy.sh — deploy's SSH key gets a session and nothing else.
#
# deploy's restricted shell is the boundary for its key, and deploy is in the
# docker group, so any SSH channel that never reaches the shell is root:
# `ssh -N -L /tmp/d.sock:/var/run/docker.sock deploy@box` would hand the
# client the Docker socket. sshd.sh's global `AllowTcpForwarding no` refuses
# that only as a side effect (it empties sshd's permitted-open list) while
# AllowStreamLocalForwarding stays yes, so one global change, say forwarding
# for supervisor, would reopen it. This Match block closes every channel but
# the session for deploy whatever the global settings are. PermitTTY keeps its
# default: the interactive deploy shell needs a terminal.
#
# Run by sshd.sh on a fresh box and by install.sh on every install and
# upgrade. Idempotent. The result is checked with `sshd -t` and against the
# effective settings for deploy (`sshd -T`); on any failure the previous
# drop-in is put back and the script exits non-zero.
set -euo pipefail
: "${DEPLOY_USER:?}"

# 00- sorts first: of two Match blocks setting a keyword, the first wins.
DROPIN="/etc/ssh/sshd_config.d/00-boxmunge-deploy.conf"

# `sshd -T` prints each setting lower-cased; these are the values deploy must get.
EXPECTED=(
    "disableforwarding yes"
    "allowtcpforwarding no"
    "allowstreamlocalforwarding no"
    "allowagentforwarding no"
    "x11forwarding no"
    "permittunnel no"
    "permituserrc no"
)

render() {
    echo "# Managed by boxmunge (bootstrap/sshd-deploy.sh); rewritten on install and upgrade."
    echo "# deploy's restricted shell is its boundary: no channel may bypass it."
    echo "Match User ${DEPLOY_USER}"
    echo "    DisableForwarding yes"
    echo "    AllowTcpForwarding no"
    echo "    AllowStreamLocalForwarding no"
    echo "    AllowAgentForwarding no"
    echo "    X11Forwarding no"
    echo "    PermitTunnel no"
    echo "    PermitUserRC no"
}

# Prints the expected settings deploy does not get, one per line; nothing when all hold.
ineffective_settings() {
    local effective line
    effective="$(/usr/sbin/sshd -T -C "user=${DEPLOY_USER},host=localhost,addr=127.0.0.1")"
    for line in "${EXPECTED[@]}"; do
        grep -qxF "${line}" <<<"${effective}" || echo "${line}"
    done
}

wanted="$(render)"
if [[ -f "${DROPIN}" && "$(cat "${DROPIN}")" == "${wanted}" ]]; then
    changed=0
else
    changed=1
fi

backup=""
if [[ "${changed}" -eq 1 ]]; then
    if [[ -f "${DROPIN}" ]]; then
        backup="$(mktemp)"
        cp -p "${DROPIN}" "${backup}"
    fi
    printf '%s\n' "${wanted}" > "${DROPIN}.tmp"
    chmod 0644 "${DROPIN}.tmp"
    mv -f "${DROPIN}.tmp" "${DROPIN}"
fi

restore() {
    if [[ "${changed}" -eq 0 ]]; then
        return 0
    fi
    if [[ -n "${backup}" ]]; then
        mv -f "${backup}" "${DROPIN}"
    else
        rm -f "${DROPIN}"
    fi
}

if ! check_output="$(/usr/sbin/sshd -t 2>&1)"; then
    restore
    echo "ERROR: sshd rejects its configuration with ${DROPIN} in place:" >&2
    echo "${check_output}" >&2
    echo "Fix the sshd configuration (sshd -t names the line), then re-run install.sh." >&2
    exit 1
fi
missing="$(ineffective_settings)"
if [[ -n "${missing}" ]]; then
    restore
    echo "ERROR: ${DROPIN} does not take effect: sshd -T does not show these for ${DEPLOY_USER}:" >&2
    while read -r line; do echo "    ${line}"; done <<<"${missing}" >&2
    echo "Check that /etc/ssh/sshd_config starts with 'Include /etc/ssh/sshd_config.d/*.conf'" \
         "and that no other file sets these for ${DEPLOY_USER} first" \
         "(sshd -T -C user=${DEPLOY_USER},host=localhost,addr=127.0.0.1), then re-run install.sh." >&2
    exit 1
fi
[[ -z "${backup}" ]] || rm -f "${backup}"

if [[ "${changed}" -eq 1 ]]; then
    # Running sessions keep their settings; every new connection gets these.
    systemctl try-reload-or-restart ssh
    echo "  sshd: forwarding closed for ${DEPLOY_USER} (${DROPIN}) + reload sent"
else
    echo "  sshd: forwarding already closed for ${DEPLOY_USER}"
fi
