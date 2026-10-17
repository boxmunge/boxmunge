#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/sshd-hardening.sh — install boxmunge's sshd drop-in
# (src/boxmunge/sshd/00-boxmunge.conf) and prove sshd enforces it.
#
# Debian's sshd_config starts with `Include /etc/ssh/sshd_config.d/*.conf`
# and sshd keeps the first value it reads for a keyword, so any drop-in
# beats the main file: a cloud image's 50-cloud-init.conf saying
# `PasswordAuthentication yes` re-enables passwords whatever the main file
# says. These settings live in 00-boxmunge.conf, which sorts first. The file
# ships in the package too, so `health` can compare the installed copy.
#
# deploy's restricted shell is the boundary for its key, and deploy is in
# the docker group, so any SSH channel that never reaches the shell is root:
# `ssh -N -L /tmp/d.sock:/var/run/docker.sock deploy@box` hands the client
# the Docker socket, and a client variable such as BASH_ENV could run code
# before the shell does. Forwarding is off for everyone (supervisor has a full
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

SOURCE="$(dirname "${BASH_SOURCE[0]}")/../src/boxmunge/sshd/00-boxmunge.conf"
DROPIN="/etc/ssh/sshd_config.d/00-boxmunge.conf"

# What sshd -T must then report (the policy, checked independently of the file).
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
# Global only (sshd refuses it in a Match block); checked for deploy.
SESSION=(
    "PermitUserEnvironment no"
)
DEPLOY_ONLY=(
    "DisableForwarding yes"
    "PermitUserRC no"
)
# The client variables deploy's sessions may receive: exactly these.
DEPLOY_ACCEPTENV="acceptenv COLORTERM
acceptenv LANG
acceptenv LC_*
acceptenv NO_COLOR"

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
# AcceptEnv values add up across Match blocks, so deploy's must be exactly
# the drop-in's: a later Match block could otherwise pass it BASH_ENV.
ineffective_settings() {
    missing_for deploy "${AUTH[@]}" "${FORWARDING[@]}" "${SESSION[@]}" "${DEPLOY_ONLY[@]}"
    missing_for supervisor "${AUTH[@]}"
    local accepted
    accepted="$(/usr/sbin/sshd -T -C "user=deploy,host=localhost,addr=127.0.0.1" \
        | grep '^acceptenv ' | LC_ALL=C sort)"
    if [[ "${accepted}" != "${DEPLOY_ACCEPTENV}" ]]; then
        echo "deploy: AcceptEnv LANG LC_* COLORTERM NO_COLOR and nothing more" \
             "(sshd -T shows: ${accepted//$'\n'/, })"
    fi
}

[[ -f "${SOURCE}" ]] || { echo "ERROR: ${SOURCE} is missing from the release bundle." >&2; exit 1; }
if cmp -s "${SOURCE}" "${DROPIN}"; then
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
    install -m 0644 "${SOURCE}" "${DROPIN}.tmp"
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
