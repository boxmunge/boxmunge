#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/auditd.sh — Auditd rules for security-relevant events.
# Called by init-host.sh. Not intended to be run standalone.
set -euo pipefail

banner() {
    echo ""
    echo "========================================================"
    echo "  $*"
    echo "========================================================"
}

banner "Hardening: Auditd (kernel audit logging)"

apt-get install -y -qq auditd

cat > /etc/audit/rules.d/boxmunge.rules <<'EOF'
# Privilege escalation
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=-1 -k privilege_escalation

# Sensitive file modifications
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# SSH key changes
-w /home/ -p wa -k ssh_keys -F name=authorized_keys
-w /root/.ssh/ -p wa -k ssh_keys

# boxmunge control plane changes
-w /opt/boxmunge/bin/ -p wa -k boxmunge_bin
-w /opt/boxmunge/config/ -p wa -k boxmunge_config
EOF

systemctl enable auditd
if ! systemctl restart auditd 2>/dev/null; then
    echo "WARNING: auditd failed to start (kernel audit support may be unavailable)."
    echo "         This is expected in some virtualised environments."
fi
augenrules --load 2>/dev/null || true

echo "Auditd installed with boxmunge rules."
