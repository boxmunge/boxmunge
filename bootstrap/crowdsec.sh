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
# Parses boxmunge-caddy's JSON access log (see acquisition below). Purpose-built
# for Caddy's native JSON format — replaces the old nginx collection, which was
# installed on the assumption Caddy emitted nginx-compatible CLF but was never
# actually fed any logs.
cscli collections install crowdsecurity/caddy 2>/dev/null || true

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

    # Caddy access log — JSON, bind-mounted out of the boxmunge-caddy container.
    # Feeds the crowdsecurity/caddy parser for HTTP-layer detection/banning.
    if ! grep -q "caddy/logs/access.log" /etc/crowdsec/acquis.yaml; then
        cat >> /etc/crowdsec/acquis.yaml <<EOF

---
source: file
filenames:
  - ${BOXMUNGE_ROOT:-/opt/boxmunge}/caddy/logs/access.log
labels:
  type: caddy
EOF
    fi
fi

systemctl enable crowdsec
systemctl restart crowdsec
systemctl enable crowdsec-firewall-bouncer
systemctl restart crowdsec-firewall-bouncer

echo "CrowdSec installed and configured."
