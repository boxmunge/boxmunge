#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/sshd.sh — sshd hardening: key-only logins, named accounts, no forwarding.
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
_set_sshd PermitRootLogin no
_set_sshd PasswordAuthentication no
_set_sshd ChallengeResponseAuthentication no
_set_sshd UsePAM yes

# Session and access limits
_set_sshd MaxAuthTries 3
_set_sshd LoginGraceTime 30
_set_sshd ClientAliveInterval 300
_set_sshd ClientAliveCountMax 2

# Restrict SSH features — deploy user must not tunnel or forward
_set_sshd AllowTcpForwarding no
_set_sshd GatewayPorts no
_set_sshd PermitTunnel no
_set_sshd X11Forwarding no

# Only named accounts may log in
_set_sshd AllowUsers "${DEPLOY_USER} supervisor"

# Note: the sshd Subsystem directive for SFTP is wired in install.sh, after
# the wrapper binary exists at /opt/boxmunge/bin/boxmunge-sftp. Doing it here
# would create a window where sshd points at a non-existent wrapper.

systemctl restart sshd
