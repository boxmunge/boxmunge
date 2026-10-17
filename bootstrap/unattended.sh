#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/unattended.sh — security updates and the nightly reboot window.
# Sourced by init-host.sh unless --no-auto-updates.
: "${ID:?}" "${REBOOT_WINDOW:?}"

if [[ "${ID}" == "ubuntu" ]]; then
    cat > /etc/apt/apt.conf.d/50unattended-upgrades <<'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
EOF
else
    install -m 0644 "$(dirname "${BASH_SOURCE[0]}")/50unattended-upgrades-debian" \
        /etc/apt/apt.conf.d/50unattended-upgrades
fi

cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "${REBOOT_WINDOW}";
EOF

systemctl enable unattended-upgrades
systemctl restart unattended-upgrades
