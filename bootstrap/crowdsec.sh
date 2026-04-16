#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/crowdsec.sh — CrowdSec installation and configuration.
# Called by init-host.sh. Not intended to be run standalone.
set -euo pipefail

SSH_PORT="${SSH_PORT:-922}"

banner() {
    echo ""
    echo "========================================================"
    echo "  $*"
    echo "========================================================"
}

banner "Hardening: CrowdSec (community threat intelligence)"

if command -v cscli &>/dev/null; then
    echo "CrowdSec already installed — skipping."
else
    # Add CrowdSec apt repository (signed, no curl-to-bash)
    curl -fsSL --proto '=https' --tlsv1.2 \
        https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh \
        -o /tmp/crowdsec-repo.sh
    bash /tmp/crowdsec-repo.sh
    rm -f /tmp/crowdsec-repo.sh
    apt-get install -y -qq crowdsec crowdsec-firewall-bouncer-iptables
fi

cscli collections install crowdsecurity/linux 2>/dev/null || true
cscli collections install crowdsecurity/sshd 2>/dev/null || true
cscli collections install crowdsecurity/nginx 2>/dev/null || true

if [[ -f /etc/crowdsec/acquis.yaml ]]; then
    if ! grep -q "journalctl" /etc/crowdsec/acquis.yaml; then
        cat >> /etc/crowdsec/acquis.yaml <<EOF

---
source: journalctl
journalctl_filter:
  - "_SYSTEMD_UNIT=sshd.service"
labels:
  type: syslog
EOF
    fi
fi

systemctl enable crowdsec
systemctl restart crowdsec
systemctl enable crowdsec-firewall-bouncer
systemctl restart crowdsec-firewall-bouncer

echo "CrowdSec installed and configured."
