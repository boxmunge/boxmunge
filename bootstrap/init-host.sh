#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# boxmunge init-host.sh
# Run as root on a fresh Debian or Ubuntu VPS to bootstrap a boxmunge-managed host.
#
# Usage:
#   sudo bash init-host.sh \
#     --hostname box01.example.com \
#     --email admin@example.com \
#     --ssh-key "ssh-ed25519 AAAA..."
#
# Optional flags:
#   --ssh-port <port>   Override default SSH port (default: 922, or $SSH_PORT env var)

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
BOXMUNGE_ROOT="/opt/boxmunge"
SSH_PORT="${SSH_PORT:-922}"
DEPLOY_USER="deploy"
REBOOT_WINDOW="${REBOOT_WINDOW:-04:00}"

HOSTNAME_ARG=""
ADMIN_EMAIL=""
SSH_KEY=""

INSTALL_AIDE=true
INSTALL_CROWDSEC=true
INSTALL_AUTO_UPDATES=true
SELF_SIGNED_TLS=false

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --hostname)  HOSTNAME_ARG="$2"; shift 2 ;;
        --email)     ADMIN_EMAIL="$2";  shift 2 ;;
        --ssh-key)   SSH_KEY="$2";      shift 2 ;;
        --ssh-port)  SSH_PORT="$2";     shift 2 ;;
        --no-aide)        INSTALL_AIDE=false;        shift ;;
        --no-crowdsec)    INSTALL_CROWDSEC=false;    shift ;;
        --no-auto-updates) INSTALL_AUTO_UPDATES=false; shift ;;
        --self-signed-tls)    SELF_SIGNED_TLS=true;           shift ;;
        *)
            echo "Unknown argument: $1" >&2
            echo "Usage: sudo bash init-host.sh --hostname HOST --email EMAIL --ssh-key KEY [--ssh-port PORT]" >&2
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Distro detection
# ---------------------------------------------------------------------------
if [[ ! -f /etc/os-release ]]; then
    echo "ERROR: /etc/os-release not found. Only Debian and Ubuntu are supported." >&2
    exit 1
fi
# shellcheck source=/dev/null
. /etc/os-release

if [[ "${ID}" != "debian" && "${ID}" != "ubuntu" ]]; then
    echo "ERROR: Unsupported distro '${ID}'. Only Debian and Ubuntu are supported." >&2
    exit 1
fi
echo "Detected distro: ${PRETTY_NAME}"

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: This script must be run as root (sudo bash init-host.sh ...)." >&2
    exit 1
fi

if [[ -f "${BOXMUNGE_ROOT}/config/boxmunge.yml" ]]; then
    echo "ERROR: boxmunge is already installed (${BOXMUNGE_ROOT}/config/boxmunge.yml exists)." >&2
    echo "       Remove it or reinstall manually if you want to re-run this script." >&2
    exit 1
fi

if [[ -z "${HOSTNAME_ARG}" ]]; then
    echo "ERROR: --hostname is required." >&2
    exit 1
fi

if [[ -z "${ADMIN_EMAIL}" ]]; then
    echo "ERROR: --email is required." >&2
    exit 1
fi

if [[ -z "${SSH_KEY}" ]]; then
    echo "ERROR: --ssh-key is required." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
banner() {
    echo ""
    echo "========================================================"
    echo "  $*"
    echo "========================================================"
}

# ---------------------------------------------------------------------------
# Step 1: System updates
# ---------------------------------------------------------------------------
echo "##BOXMUNGE:STEP:1:15:Updating system packages"
banner "Step 1/14: System updates"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq

# ---------------------------------------------------------------------------
# Step 2: Install required packages
# ---------------------------------------------------------------------------
echo "##BOXMUNGE:STEP:2:15:Installing required packages"
banner "Step 2/14: Installing required packages"
apt-get install -y -qq \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    ufw \
    fail2ban \
    unattended-upgrades \
    python3 \
    python3-pip \
    python3-venv \
    python3-yaml \
    sudo \
    git \
    age \
    rclone \
    jq

# ---------------------------------------------------------------------------
# Step 3: Install Docker (official repo)
# ---------------------------------------------------------------------------
echo "##BOXMUNGE:STEP:3:15:Installing Docker"
banner "Step 3/14: Installing Docker"
if command -v docker &>/dev/null; then
    echo "Docker already installed — skipping."
else
    # Add Docker's official GPG key
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL "https://download.docker.com/linux/${ID}/gpg" \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg

    # Set up the repository
    echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/${ID} ${VERSION_CODENAME} stable" \
        > /etc/apt/sources.list.d/docker.list

    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

    systemctl enable docker
    systemctl start docker
fi

# ---------------------------------------------------------------------------
# Step 4: Create deploy user (BEFORE SSH hardening to avoid lockout)
# ---------------------------------------------------------------------------
echo "##BOXMUNGE:STEP:4:15:Creating users and SSH keys"
banner "Step 4/14: Creating deploy user (restricted boxmunge shell)..."
if id "${DEPLOY_USER}" &>/dev/null; then
    echo "User '${DEPLOY_USER}' already exists — skipping useradd."
    current_shell=$(getent passwd "${DEPLOY_USER}" | cut -d: -f7)
    if [ "$current_shell" = "/bin/bash" ]; then
        chsh -s /opt/boxmunge/bin/boxmunge-shell "${DEPLOY_USER}"
        echo "Changed deploy shell from bash to boxmunge-shell"
    fi
else
    useradd -m -s /opt/boxmunge/bin/boxmunge-shell "${DEPLOY_USER}"
fi
usermod -aG docker "${DEPLOY_USER}"

banner "Step 4b/14: Creating supervisor user (full shell access)..."
if id supervisor &>/dev/null; then
    echo "User 'supervisor' already exists — skipping useradd."
else
    useradd -m -s /bin/bash supervisor
fi
usermod -aG docker,deploy supervisor

# SSH keys for both users
for user in "${DEPLOY_USER}" supervisor; do
    user_home=$(getent passwd "$user" | cut -d: -f6)
    ssh_dir="$user_home/.ssh"
    mkdir -p "$ssh_dir"
    echo "$SSH_KEY" > "$ssh_dir/authorized_keys"
    chmod 700 "$ssh_dir"
    chmod 600 "$ssh_dir/authorized_keys"
    chown -R "$user:$user" "$ssh_dir"
done

# Only supervisor gets sudo
banner "Step 4c/14: Configuring sudo access for supervisor..."
cat > /etc/sudoers.d/boxmunge << 'SUDOEOF'
supervisor ALL=(ALL) NOPASSWD: ALL
SUDOEOF
chmod 440 /etc/sudoers.d/boxmunge

# Remove deploy from sudo if present (v1 migration)
if groups "${DEPLOY_USER}" 2>/dev/null | grep -q sudo; then
    gpasswd -d "${DEPLOY_USER}" sudo 2>/dev/null || true
    echo "Removed ${DEPLOY_USER} from sudo group"
fi

echo "Deploy user '${DEPLOY_USER}' ready with restricted shell and SSH key installed."
echo "Supervisor user 'supervisor' ready with full shell and SSH key installed."

# ---------------------------------------------------------------------------
# Step 5: Configure SSH (deploy user must exist first — lockout prevention)
# ---------------------------------------------------------------------------
echo "##BOXMUNGE:STEP:5:15:Configuring SSH"
banner "Step 5/14: Configuring SSH (port ${SSH_PORT})"
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

# Replace the global SFTP subsystem with our wrapper.
# Modern scp (OpenSSH 9+) uses the SFTP protocol, so scp uploads invoke
# the sftp subsystem instead of the user's login shell. Our wrapper checks
# if the user is deploy and routes through the reception handler; for all
# other users it falls through to the real sftp-server.
sed -i 's|^Subsystem.*sftp.*|Subsystem sftp /opt/boxmunge/bin/boxmunge-sftp|' "${SSHD_CONFIG}"

systemctl restart sshd

# ---------------------------------------------------------------------------
# Step 6: Configure firewall (ufw)
# ---------------------------------------------------------------------------
echo "##BOXMUNGE:STEP:6:15:Configuring firewall"
banner "Step 6/14: Configuring firewall (ufw)"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow "${SSH_PORT}/tcp" comment "SSH"
ufw allow 80/tcp  comment "HTTP"
ufw allow 443/tcp comment "HTTPS"
ufw --force enable

# ---------------------------------------------------------------------------
# Step 7: Configure fail2ban
# ---------------------------------------------------------------------------
echo "##BOXMUNGE:STEP:7:15:Configuring fail2ban"
banner "Step 7/14: Configuring fail2ban"
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime  = 1800
findtime = 600
maxretry = 10

[sshd]
enabled = true
port    = ${SSH_PORT}
EOF

systemctl enable fail2ban
systemctl restart fail2ban

# ---------------------------------------------------------------------------
# Step 7b: CrowdSec, AIDE, Auditd, AppArmor
# ---------------------------------------------------------------------------
echo "##BOXMUNGE:STEP:8:15:Installing security tools"
if [[ "${INSTALL_CROWDSEC}" == "true" ]]; then
    source "$(dirname "$0")/crowdsec.sh"
else
    echo "Skipping CrowdSec (--no-crowdsec)"
fi

if [[ "${INSTALL_AIDE}" == "true" ]]; then
    source "$(dirname "$0")/aide.sh"
else
    echo "Skipping AIDE (--no-aide)"
fi

source "$(dirname "$0")/auditd.sh"
source "$(dirname "$0")/apparmor.sh"

# ---------------------------------------------------------------------------
# Step 8: Configure unattended-upgrades
# ---------------------------------------------------------------------------
echo "##BOXMUNGE:STEP:9:15:Configuring automatic updates"
if [[ "${INSTALL_AUTO_UPDATES}" == "true" ]]; then
    banner "Step 8/14: Configuring unattended-upgrades"
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
        cat > /etc/apt/apt.conf.d/50unattended-upgrades <<'EOF'
Unattended-Upgrade::Allowed-Origins {
    "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
EOF
    fi

    cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "${REBOOT_WINDOW}";
EOF

    systemctl enable unattended-upgrades
    systemctl restart unattended-upgrades
else
    echo "Skipping unattended-upgrades (--no-auto-updates)"
fi

# ---------------------------------------------------------------------------
# Step 9: Create directory layout
# ---------------------------------------------------------------------------
echo "##BOXMUNGE:STEP:10:15:Creating directory layout"
banner "Step 9/14: Creating /opt/boxmunge directory tree"
install -d -m 755 -o root -g root \
    "${BOXMUNGE_ROOT}" \
    "${BOXMUNGE_ROOT}/bin"

install -d -m 750 -o root -g "${DEPLOY_USER}" \
    "${BOXMUNGE_ROOT}/config" \
    "${BOXMUNGE_ROOT}/caddy"

# caddy/sites needs group write so deploy can write generated site configs
install -d -m 770 -o root -g "${DEPLOY_USER}" \
    "${BOXMUNGE_ROOT}/caddy/sites"

install -d -m 755 -o root -g root \
    "${BOXMUNGE_ROOT}/templates" \
    "${BOXMUNGE_ROOT}/templates/project" \
    "${BOXMUNGE_ROOT}/docs"

install -d -m 755 -o "${DEPLOY_USER}" -g "${DEPLOY_USER}" \
    "${BOXMUNGE_ROOT}/projects" \
    "${BOXMUNGE_ROOT}/state" \
    "${BOXMUNGE_ROOT}/state/health" \
    "${BOXMUNGE_ROOT}/state/deploy" \
    "${BOXMUNGE_ROOT}/logs"

install -d -m 755 -o "${DEPLOY_USER}" -g "${DEPLOY_USER}" "${BOXMUNGE_ROOT}/inbox"
install -d -m 755 -o "${DEPLOY_USER}" -g "${DEPLOY_USER}" "${BOXMUNGE_ROOT}/inbox/.tmp"
install -d -m 755 -o "${DEPLOY_USER}" -g "${DEPLOY_USER}" "${BOXMUNGE_ROOT}/inbox/.consumed"

# ---------------------------------------------------------------------------
# Step 10: Configure Docker logging
# ---------------------------------------------------------------------------
echo "##BOXMUNGE:STEP:11:15:Configuring Docker logging"
banner "Step 10/14: Configuring Docker logging defaults"
install -d -m 755 /etc/docker
cat > /etc/docker/daemon.json <<'EOF'
{
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "50m",
        "max-file": "5"
    }
}
EOF
systemctl restart docker

# ---------------------------------------------------------------------------
# Step 11: Create Docker network and backup key; write boxmunge.yml
# ---------------------------------------------------------------------------
echo "##BOXMUNGE:STEP:12:15:Configuring Docker network and credentials"
banner "Step 11/14: Docker network, backup key, boxmunge.yml"

# Docker network
if docker network inspect boxmunge-proxy &>/dev/null 2>&1; then
    echo "Docker network 'boxmunge-proxy' already exists — skipping."
else
    docker network create boxmunge-proxy
fi

# Backup encryption key (age identity)
age-keygen -o "${BOXMUNGE_ROOT}/config/backup.key" 2>/dev/null
BACKUP_PUBKEY="$(age-keygen -y "${BOXMUNGE_ROOT}/config/backup.key")"
chmod 640 "${BOXMUNGE_ROOT}/config/backup.key"
chown root:"${DEPLOY_USER}" "${BOXMUNGE_ROOT}/config/backup.key"

# Write boxmunge.yml from template values
cat > "${BOXMUNGE_ROOT}/config/boxmunge.yml" <<EOF
# boxmunge host configuration
# Managed by boxmunge. Edit via \`boxmunge config\` commands.

hostname: ${HOSTNAME_ARG}
ssh_port: ${SSH_PORT}
admin_email: ${ADMIN_EMAIL}

pushover:
  user_key: ""
  app_token: ""

backup_remote: ""

health:
  check_interval_minutes: 5
  alert_threshold: 3

reboot:
  auto_reboot: true
  reboot_window: "${REBOOT_WINDOW}"

logging:
  docker_max_size: "50m"
  docker_max_file: 5
EOF
if [ "$SELF_SIGNED_TLS" = "true" ]; then
    echo "tls_mode: internal" >> "${BOXMUNGE_ROOT}/config/boxmunge.yml"
fi
chmod 640 "${BOXMUNGE_ROOT}/config/boxmunge.yml"
chown root:"${DEPLOY_USER}" "${BOXMUNGE_ROOT}/config/boxmunge.yml"

# ---------------------------------------------------------------------------
# Step 12: Install boxmunge CLI
# ---------------------------------------------------------------------------
echo "##BOXMUNGE:STEP:13:15:Preparing PATH and login shell"
banner "Step 12/14: Adding boxmunge to PATH"

cat > /etc/profile.d/boxmunge.sh <<EOF
# boxmunge CLI — added by init-host.sh
export PATH="\${PATH}:${BOXMUNGE_ROOT}/bin"
EOF
chmod 644 /etc/profile.d/boxmunge.sh

# Register boxmunge-shell as a valid login shell
if ! grep -q boxmunge-shell /etc/shells; then
    echo "/opt/boxmunge/bin/boxmunge-shell" >> /etc/shells
fi

# ---------------------------------------------------------------------------
# Step 13: Write Caddyfile, compose.yml, start Caddy
# ---------------------------------------------------------------------------
echo "##BOXMUNGE:STEP:14:15:Deploying Caddy reverse proxy"
banner "Step 13/14: Deploying Caddy reverse proxy"

if [ "$SELF_SIGNED_TLS" = "true" ]; then
cat > "${BOXMUNGE_ROOT}/caddy/Caddyfile" <<EOF
{
    email ${ADMIN_EMAIL}
    local_certs
}

import /etc/caddy/sites/*.conf
EOF
else
cat > "${BOXMUNGE_ROOT}/caddy/Caddyfile" <<EOF
{
    email ${ADMIN_EMAIL}
}

import /etc/caddy/sites/*.conf
EOF
fi
chmod 640 "${BOXMUNGE_ROOT}/caddy/Caddyfile"
chown root:"${DEPLOY_USER}" "${BOXMUNGE_ROOT}/caddy/Caddyfile"

cat > "${BOXMUNGE_ROOT}/caddy/compose.yml" <<'EOF'
# Caddy reverse proxy — managed by boxmunge
# Do not edit directly. Changes are made via boxmunge commands.

services:
  caddy:
    image: caddy:2-alpine
    container_name: boxmunge-caddy
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - ./sites:/etc/caddy/sites:ro
      - caddy_data:/data
      - caddy_config:/config
    networks:
      - boxmunge-proxy
    read_only: true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    healthcheck:
      test: ["CMD", "caddy", "validate", "--config", "/etc/caddy/Caddyfile"]
      interval: 30s
      timeout: 5s
      retries: 3

volumes:
  caddy_data:
  caddy_config:

networks:
  boxmunge-proxy:
    external: true
EOF
chmod 640 "${BOXMUNGE_ROOT}/caddy/compose.yml"
chown root:"${DEPLOY_USER}" "${BOXMUNGE_ROOT}/caddy/compose.yml"

# Start Caddy
docker compose -f "${BOXMUNGE_ROOT}/caddy/compose.yml" up -d
CADDY_STATUS="$(docker inspect --format='{{.State.Status}}' boxmunge-caddy 2>/dev/null || echo 'unknown')"

# ---------------------------------------------------------------------------
# Step 14/14: OS hardening
# ---------------------------------------------------------------------------
echo "##BOXMUNGE:STEP:15:15:OS hardening"
banner "Step 14/14: OS hardening"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
bash "${SCRIPT_DIR}/harden.sh"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "###################################################################"
echo "#                  boxmunge init complete                         #"
echo "###################################################################"
echo ""
echo "  Hostname   : ${HOSTNAME_ARG}"
echo "  SSH port   : ${SSH_PORT}"
echo "  Deploy user: ${DEPLOY_USER}"
echo "  Root dir   : ${BOXMUNGE_ROOT}"
echo "  Caddy      : ${CADDY_STATUS}"
echo ""
echo "  *** BACKUP KEY — SAVE THIS FILE TO A SECURE LOCATION ***"
echo "  ${BOXMUNGE_ROOT}/config/backup.key"
echo ""
echo "  Public key: ${BACKUP_PUBKEY}"
echo ""
echo "-------------------------------------------------------------------"
echo "  Next steps:"
echo ""
echo "  1. Copy your backup key to a secure password manager NOW."
echo ""
echo "  2. Reconnect as supervisor for administration:"
echo "       ssh -p ${SSH_PORT} supervisor@${HOSTNAME_ARG}"
echo ""
echo "  3. Deploy via restricted shell:"
echo "       ssh -p ${SSH_PORT} ${DEPLOY_USER}@${HOSTNAME_ARG} \"help\""
echo ""
echo "  4. Upload bundles:"
echo "       scp -P ${SSH_PORT} bundle.tar.gz ${DEPLOY_USER}@${HOSTNAME_ARG}:"
echo ""
echo "  5. Configure backup remote in ${BOXMUNGE_ROOT}/config/boxmunge.yml"
echo "     then test with: boxmunge backup <project-name>"
echo "###################################################################"
echo ""
