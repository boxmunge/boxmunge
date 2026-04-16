#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/aide.sh — AIDE file integrity monitoring for the control plane.
# Called by init-host.sh. Not intended to be run standalone.
set -euo pipefail

BOXMUNGE_ROOT="${BOXMUNGE_ROOT:-/opt/boxmunge}"

banner() {
    echo ""
    echo "========================================================"
    echo "  $*"
    echo "========================================================"
}

banner "Hardening: AIDE (file integrity monitoring)"

apt-get install -y -qq aide

cat > /etc/aide/aide.conf.d/90_boxmunge.conf <<EOF
# boxmunge control plane
${BOXMUNGE_ROOT}/bin Full
${BOXMUNGE_ROOT}/config Full

# Critical system files
/etc/ssh Full
/etc/sudoers Full
/etc/sudoers.d Full
/etc/sysctl.d Full
/etc/passwd Full
/etc/shadow Full
/etc/group Full

# systemd units
/etc/systemd/system Full
EOF

echo "Initialising AIDE database (this may take a minute)..."
if ! aideinit 2>&1 && ! aide --init 2>&1; then
    echo "WARNING: AIDE database initialisation failed. Run 'aideinit' manually." >&2
fi

cat > /etc/cron.daily/boxmunge-aide-check <<'CRONEOF'
#!/bin/sh
RESULT=$(/usr/bin/aide --check 2>&1 || true)
if echo "$RESULT" | grep -q "changed entries"; then
    echo "$RESULT" | logger -t boxmunge-aide -p auth.warning
fi
CRONEOF
chmod +x /etc/cron.daily/boxmunge-aide-check

echo "AIDE installed and initialised."
