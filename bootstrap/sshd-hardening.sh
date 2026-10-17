#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/sshd-hardening.sh — boxmunge's sshd settings, as a drop-in that wins.
#
# Debian's sshd_config starts with `Include /etc/ssh/sshd_config.d/*.conf`
# and sshd keeps the first value it reads for a keyword, so any drop-in
# beats the main file: a cloud image's 50-cloud-init.conf saying
# `PasswordAuthentication yes` re-enables passwords whatever the main file
# says. These settings live in 00-boxmunge.conf, which sorts first.
#
# deploy's restricted shell is the boundary for its key, and deploy is in
# the docker group, so any SSH channel that never reaches the shell is root:
# `ssh -N -L /tmp/d.sock:/var/run/docker.sock deploy@box` hands the client
# the Docker socket. Forwarding is off for everyone (supervisor has a full
# shell and needs none), and a Match block keeps it off for deploy even if
# an operator's own Match block opens it for supervisor. A Match block in an
# included file ends with that file, so it cannot capture the main file's
# settings. PermitTTY keeps its default: the interactive deploy shell needs
# a terminal. Port, AllowUsers and the session limits stay in sshd.sh, the
# SFTP Subsystem in install.sh.
#
# Run by sshd.sh on a fresh box and by install.sh on every install and
# upgrade. Idempotent. The result is checked with `sshd -t` and against the
# settings sshd would actually give deploy and supervisor (`sshd -T -C`); on
# any failure the previous drop-in is put back and the script exits non-zero.
set -euo pipefail
: "${DEPLOY_USER:?}"

DROPIN="/etc/ssh/sshd_config.d/00-boxmunge.conf"

AUTH=(
    "PasswordAuthentication no"
    "KbdInteractiveAuthentication no"
    "PermitRootLogin no"
)
FORWARDING=(
    "X11Forwarding no"
    "AllowTcpForwarding no"
    "AllowStreamLocalForwarding no"
    "AllowAgentForwarding no"
    "PermitTunnel no"
    "GatewayPorts no"
)
DEPLOY_ONLY=(
    "DisableForwarding yes"
    "PermitUserRC no"
)

render() {
    local line
    echo "# Managed by boxmunge (bootstrap/sshd-hardening.sh); rewritten on install and upgrade."
    echo "# Sorts first so these values win over later drop-ins (sshd keeps the first)."
    for line in "${AUTH[@]}" "${FORWARDING[@]}"; do echo "${line}"; done
    echo ""
    echo "# deploy's restricted shell is its boundary: no channel may bypass it."
    echo "Match User ${DEPLOY_USER}"
    for line in "${FORWARDING[@]}" "${DEPLOY_ONLY[@]}"; do echo "    ${line}"; done
}

# missing_for <user> <setting>...: prints the settings sshd would not give
# <user>, one per line.
missing_for() {
    local user="$1" effective line
    shift
    effective="$(/usr/sbin/sshd -T -C "user=${user},host=localhost,addr=127.0.0.1")"
    for line in "$@"; do
        # `sshd -T` prints keywords lower-cased.
        grep -qxF "${line,,}" <<<"${effective}" || echo "${user}: ${line}"
    done
}

# Every account gets key-only logins. Forwarding is checked for deploy only:
# an operator may open it for supervisor in a Match block of their own.
ineffective_settings() {
    missing_for "${DEPLOY_USER}" "${AUTH[@]}" "${FORWARDING[@]}" "${DEPLOY_ONLY[@]}"
    missing_for supervisor "${AUTH[@]}"
}

content="$(render)"
if [[ -f "${DROPIN}" && "$(cat "${DROPIN}")" == "${content}" ]]; then
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
    printf '%s\n' "${content}" > "${DROPIN}.tmp"
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
    echo "ERROR: ${DROPIN} does not take effect; sshd -T does not show:" >&2
    while read -r line; do echo "    ${line}"; done <<<"${missing}" >&2
    echo "Check that /etc/ssh/sshd_config starts with 'Include /etc/ssh/sshd_config.d/*.conf'" \
         "and that no file read before ${DROPIN} sets these" \
         "(sshd -T -C user=<user>,host=localhost,addr=127.0.0.1), then re-run install.sh." >&2
    exit 1
fi
[[ -z "${backup}" ]] || rm -f "${backup}"

if [[ "${changed}" -eq 1 ]]; then
    # Running sessions keep their settings; every new connection gets these.
    systemctl try-reload-or-restart ssh
    echo "  sshd: hardening applied (${DROPIN}) + reload sent"
else
    echo "  sshd: hardening already applied"
fi
