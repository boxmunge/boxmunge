#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/sshd.sh — sshd: port, named accounts, session limits; then the
# drop-in with key-only logins and no forwarding (sshd-hardening.sh).
# Sourced by init-host.sh after deploy and supervisor exist (lockout prevention).
: "${SSH_PORT:?}" "${DEPLOY_USER:?}"

SSHD_CONFIG="/etc/ssh/sshd_config"

# Apply settings — add if missing, replace if present
_set_sshd() {
    local key="$1" val="$2"
    if grep -qE "^#?${key}" "${SSHD_CONFIG}"; then
        sed -i "s|^#\?${key}.*|${key} ${val}|" "${SSHD_CONFIG}"
    else
        echo "${key} ${val}" >> "${SSHD_CONFIG}"
    fi
}

_set_sshd Port            "${SSH_PORT}"
_set_sshd UsePAM yes

# Session and access limits
_set_sshd MaxAuthTries 3
_set_sshd LoginGraceTime 30
_set_sshd ClientAliveInterval 300
_set_sshd ClientAliveCountMax 2

# Only named accounts may log in
_set_sshd AllowUsers "${DEPLOY_USER} supervisor"

# Note: the sshd Subsystem directive for SFTP is wired in install.sh, after
# the wrapper binary exists at /opt/boxmunge/bin/boxmunge-sftp. Doing it here
# would create a window where sshd points at a non-existent wrapper.

# Logins and forwarding. Before the restart, so sshd never serves without it.
DEPLOY_USER="${DEPLOY_USER}" bash "$(dirname "${BASH_SOURCE[0]}")/sshd-hardening.sh"

systemctl restart sshd
