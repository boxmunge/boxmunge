#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/apparmor.sh — AppArmor profiles for boxmunge platform containers.
# Called by init-host.sh. Not intended to be run standalone.
set -euo pipefail

banner() {
    echo ""
    echo "========================================================"
    echo "  $*"
    echo "========================================================"
}

banner "Hardening: AppArmor profiles for platform containers"

apt-get install -y -qq apparmor apparmor-utils

cat > /etc/apparmor.d/boxmunge-caddy <<'EOF'
#include <tunables/global>

profile boxmunge-caddy flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  network inet stream,
  network inet6 stream,

  /etc/caddy/** r,
  /data/** rw,
  /config/** rw,

  deny /proc/*/net/** r,
  deny /sys/** rw,
}
EOF

cat > /etc/apparmor.d/boxmunge-system <<'EOF'
#include <tunables/global>

profile boxmunge-system flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  /config/** r,
  /projects/** rw,
  /tmp/** rw,

  network inet stream,
  network inet6 stream,

  deny network raw,
  deny ptrace,
  deny mount,
}
EOF

echo "Loading AppArmor profiles..."
if ! apparmor_parser -r /etc/apparmor.d/boxmunge-caddy 2>&1; then
    echo "WARNING: Failed to load boxmunge-caddy AppArmor profile." >&2
fi
if ! apparmor_parser -r /etc/apparmor.d/boxmunge-system 2>&1; then
    echo "WARNING: Failed to load boxmunge-system AppArmor profile." >&2
fi

echo "AppArmor profiles installed for Caddy and system containers."
