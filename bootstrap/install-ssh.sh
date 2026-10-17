#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/install-ssh.sh — deploy's SSH entry points and sshd's settings.
# Sourced by install.sh on every install and upgrade, with BOXMUNGE_ROOT and
# SCRIPT_DIR set, after the venv and before the upgrade shim.
: "${BOXMUNGE_ROOT:?}" "${SCRIPT_DIR:?}"

# deploy's login shell runs before any check, with whatever environment the
# SSH client got through: sh reads no startup file for a script (bash would
# run $BASH_ENV) and python -I ignores PYTHON* variables. The shell then
# drops the rest (shell.restrict_environment).
cat > "${BOXMUNGE_ROOT}/bin/boxmunge-shell" <<'WRAPPER'
#!/bin/sh
exec /opt/boxmunge/env-active/bin/python -I /opt/boxmunge/env-active/bin/boxmunge-shell "$@"
WRAPPER
chmod 755 "${BOXMUNGE_ROOT}/bin/boxmunge-shell"

# boxmunge-sftp is a real script in scripts/ so the upgrade shim's
# self-update loop can refresh it from a release bundle (audit C-NEW-6).
# Copy from the bundle, not an inline heredoc.
cp "${SCRIPT_DIR}/scripts/boxmunge-sftp" "${BOXMUNGE_ROOT}/bin/boxmunge-sftp"
chmod 755 "${BOXMUNGE_ROOT}/bin/boxmunge-sftp"

# ---------------------------------------------------------------------------
# Wire sshd's SFTP subsystem to boxmunge-sftp.
#
# The wrapper refuses SFTP for deploy (sftp-server cannot be confined to the
# inbox without chrooting every deploy session, and unconfined it exposes
# everything deploy can read and write) and execs the real sftp-server for
# everyone else. deploy uploads with legacy scp (`scp -O`), which the
# restricted shell receives through `scp -t`. Idempotent; runs on every
# install/upgrade so the wiring cannot drift.
# ---------------------------------------------------------------------------
SSHD_CONFIG="/etc/ssh/sshd_config"
SFTP_SUBSYSTEM_LINE="Subsystem sftp ${BOXMUNGE_ROOT}/bin/boxmunge-sftp"
if grep -qxF "${SFTP_SUBSYSTEM_LINE}" "${SSHD_CONFIG}"; then
    echo "  sshd Subsystem already wired to boxmunge-sftp"
else
    if grep -qE '^Subsystem[[:space:]]+sftp[[:space:]]' "${SSHD_CONFIG}"; then
        sed -i "s|^Subsystem[[:space:]]\\+sftp[[:space:]].*|${SFTP_SUBSYSTEM_LINE}|" "${SSHD_CONFIG}"
    else
        printf '\n%s\n' "${SFTP_SUBSYSTEM_LINE}" >> "${SSHD_CONFIG}"
    fi
    /usr/sbin/sshd -t
    systemctl reload ssh 2>/dev/null || systemctl reload sshd
    echo "  sshd Subsystem rewired to boxmunge-sftp + reload sent"
fi

# Key-only logins and no forwarding, as a drop-in that wins over cloud-init's
# (the script says why). It fails the install if sshd would not enforce it.
# The upgrade shim re-runs install.sh whenever install.sh, bootstrap/ or the
# drop-in changes (the installer fingerprint), so every box gets the release's.
bash "${SCRIPT_DIR}/bootstrap/sshd-hardening.sh"
