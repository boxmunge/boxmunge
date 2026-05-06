#!/usr/bin/env bash
# boxmunge install.sh
# Installs boxmunge on a Debian or Ubuntu VPS.
#
# Fresh install (runs full system bootstrap first):
#   sudo bash install.sh --hostname HOST --email EMAIL --ssh-key KEY [--ssh-port PORT]
#
# Upgrade (SSH in as deploy user, elevate with sudo):
#   sudo bash install.sh

set -euo pipefail

BOXMUNGE_ROOT="/opt/boxmunge"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ---------------------------------------------------------------------------
# Cosign — pinned version + checksum.
#
# Used by the upgrade shim to verify the keyless signature on SHA256SUMS for
# every release before installing. Hard-required, no fallback. Pin the binary
# version + checksum so a compromised github.com release page can't swap in
# a malicious cosign. Source of truth for the checksum is upstream's
# `cosign_checksums.txt` for the same release.
# ---------------------------------------------------------------------------
export COSIGN_VERSION="v2.4.1"
export COSIGN_SHA256="8b24b946dd5809c6bd93de08033bcf6bc0ed7d336b7785787c080f574b89249b"

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------
if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Install cosign (used by the upgrade shim to verify release signatures).
#
# Idempotent: if the pinned version is already installed, this is a no-op.
# Failure is fatal — the upgrade shim hard-requires cosign and would refuse
# to install future releases otherwise.
# ---------------------------------------------------------------------------
install_cosign() {
    if command -v cosign >/dev/null 2>&1; then
        local installed_version
        installed_version="$(cosign version 2>&1 | grep -oE 'GitVersion:[[:space:]]*v[0-9.]+' | head -1 | awk '{print $NF}')"
        if [[ "${installed_version}" == "${COSIGN_VERSION}" ]]; then
            return 0
        fi
        echo "  cosign present (version='${installed_version}'), upgrading to ${COSIGN_VERSION}"
    fi
    echo "  Installing cosign ${COSIGN_VERSION}..."
    local url="https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64"
    curl -sSLf "${url}" -o /tmp/cosign
    echo "${COSIGN_SHA256}  /tmp/cosign" | sha256sum -c -
    install -m 0755 /tmp/cosign /usr/local/bin/cosign
    rm -f /tmp/cosign
}

# ---------------------------------------------------------------------------
# Trivy install — required for CVE scanning (boxmunge security scan).
# Failure is fatal — without Trivy, the daily CVE scan timer cannot run.
#
# Trivy is installed from Aqua Security's official Debian repo. The signing
# key is fetched once and dearmored to /usr/share/keyrings/trivy.gpg. The
# repo URL points at "generic main" which serves all Debian/Ubuntu releases.
# ---------------------------------------------------------------------------
install_trivy() {
    if command -v trivy >/dev/null 2>&1; then
        return 0
    fi
    echo "  Installing Trivy (CVE scanner)..."

    # Fetch and dearmor the signing key into the trusted keyrings dir.
    if [[ ! -f /usr/share/keyrings/trivy.gpg ]]; then
        curl -sSLf https://aquasecurity.github.io/trivy-repo/deb/public.key \
            | gpg --dearmor -o /usr/share/keyrings/trivy.gpg
    fi

    # Add the repo definition (idempotent — overwrites if present).
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
        > /etc/apt/sources.list.d/trivy.list

    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y trivy
}

echo ""
echo "========================================================"
echo "  Ensuring cosign is installed (release signature verification)"
echo "========================================================"
install_cosign

echo ""
echo "========================================================"
echo "  Ensuring Trivy is installed (CVE vulnerability scanner)"
echo "========================================================"
install_trivy

# ---------------------------------------------------------------------------
# System bootstrap (fresh install only)
# ---------------------------------------------------------------------------
if [[ ! -f "${BOXMUNGE_ROOT}/config/boxmunge.yml" ]]; then
    if [[ $# -eq 0 ]]; then
        echo "ERROR: Fresh install detected — system bootstrap arguments required." >&2
        echo "Usage: sudo bash install.sh --hostname HOST --email EMAIL --ssh-key KEY [--ssh-port PORT]" >&2
        exit 1
    fi
    bash "${SCRIPT_DIR}/bootstrap/init-host.sh" "$@"
else
    echo "Existing installation detected — upgrading boxmunge package only."
fi

# ---------------------------------------------------------------------------
# Migrate backup key from passphrase to age identity (0.1.1 -> 0.1.2)
# ---------------------------------------------------------------------------
KEY_FILE="${BOXMUNGE_ROOT}/config/backup.key"
if [[ -f "${KEY_FILE}" ]] && ! grep -q "^AGE-SECRET-KEY-" "${KEY_FILE}"; then
    echo ""
    echo "========================================================"
    echo "  Migrating backup key to age identity format"
    echo "========================================================"
    mv "${KEY_FILE}" "${KEY_FILE}.old-passphrase"
    age-keygen -o "${KEY_FILE}" 2>/dev/null
    chown root:deploy "${KEY_FILE}"
    chmod 640 "${KEY_FILE}"
    PUBKEY="$(age-keygen -y "${KEY_FILE}")"
    echo "  New public key: ${PUBKEY}"
    echo "  Old passphrase key saved as: ${KEY_FILE}.old-passphrase"
    echo "  NOTE: Existing backups used the old passphrase."
    echo "        New backups will use the age identity."
fi

# ---------------------------------------------------------------------------
# Migrate v0.2.x single-venv layout to v0.3.0+ two-venv layout
# ---------------------------------------------------------------------------
if [[ -d "${BOXMUNGE_ROOT}/venv" && ! -d "${BOXMUNGE_ROOT}/env-a" ]]; then
    echo ""
    echo "========================================================"
    echo "  Migrating from single-venv to two-venv layout"
    echo "========================================================"
    # The old venv contains nothing recoverable for us — every package is
    # about to be reinstalled in the next step. Don't `mv`: the venv's
    # shebangs are absolute paths to /opt/boxmunge/venv/bin/python3 and
    # don't survive a rename. Wipe and recreate fresh.
    rm -rf "${BOXMUNGE_ROOT}/venv"
    mkdir -p "${BOXMUNGE_ROOT}/upgrade-state"
    chown root:deploy "${BOXMUNGE_ROOT}/upgrade-state"
    chmod 770 "${BOXMUNGE_ROOT}/upgrade-state"
    echo "a" > "${BOXMUNGE_ROOT}/upgrade-state/active-slot"
    chown root:deploy "${BOXMUNGE_ROOT}/upgrade-state/active-slot"
    chmod 660 "${BOXMUNGE_ROOT}/upgrade-state/active-slot"
    echo "{}" > "${BOXMUNGE_ROOT}/upgrade-state/blocklist.json"
    chown root:deploy "${BOXMUNGE_ROOT}/upgrade-state/blocklist.json"
    chmod 660 "${BOXMUNGE_ROOT}/upgrade-state/blocklist.json"
    python3 -m venv "${BOXMUNGE_ROOT}/env-a"
    ln -sfn "${BOXMUNGE_ROOT}/env-a" "${BOXMUNGE_ROOT}/env-active"
    echo "  Layout migrated: old venv removed, env-a created, env-active symlink in place"
fi

# ---------------------------------------------------------------------------
# Migrate project registry from config/ (root-only) to state/ (deploy-writable)
# ---------------------------------------------------------------------------
OLD_REGISTRY="${BOXMUNGE_ROOT}/config/projects.txt"
NEW_REGISTRY="${BOXMUNGE_ROOT}/state/projects.txt"
if [[ -f "${OLD_REGISTRY}" && ! -f "${NEW_REGISTRY}" ]]; then
    echo ""
    echo "========================================================"
    echo "  Moving project registry to state/ (deploy-writable)"
    echo "========================================================"
    mv "${OLD_REGISTRY}" "${NEW_REGISTRY}"
    chown deploy:deploy "${NEW_REGISTRY}"
    chmod 644 "${NEW_REGISTRY}"
    echo "  Registry moved: ${OLD_REGISTRY} -> ${NEW_REGISTRY}"
fi

# ---------------------------------------------------------------------------
# Install boxmunge Python package into isolated venv
# ---------------------------------------------------------------------------
echo ""
echo "========================================================"
echo "  Installing boxmunge package"
echo "========================================================"

# For fresh installs, set up env-a as the active slot
if [[ ! -L "${BOXMUNGE_ROOT}/env-active" ]]; then
    mkdir -p "${BOXMUNGE_ROOT}/upgrade-state"
    chown root:deploy "${BOXMUNGE_ROOT}/upgrade-state"
    chmod 770 "${BOXMUNGE_ROOT}/upgrade-state"
    echo "a" > "${BOXMUNGE_ROOT}/upgrade-state/active-slot"
    chown root:deploy "${BOXMUNGE_ROOT}/upgrade-state/active-slot"
    chmod 660 "${BOXMUNGE_ROOT}/upgrade-state/active-slot"
    echo "{}" > "${BOXMUNGE_ROOT}/upgrade-state/blocklist.json"
    chown root:deploy "${BOXMUNGE_ROOT}/upgrade-state/blocklist.json"
    chmod 660 "${BOXMUNGE_ROOT}/upgrade-state/blocklist.json"
    python3 -m venv "${BOXMUNGE_ROOT}/env-a"
    ln -sfn "${BOXMUNGE_ROOT}/env-a" "${BOXMUNGE_ROOT}/env-active"
fi

# Ensure upgrade-state perms allow deploy access (idempotent — fixes existing v0.3.0/v0.3.1 installs)
if [[ -d "${BOXMUNGE_ROOT}/upgrade-state" ]]; then
    chown -R root:deploy "${BOXMUNGE_ROOT}/upgrade-state"
    chmod 770 "${BOXMUNGE_ROOT}/upgrade-state"
    [[ -f "${BOXMUNGE_ROOT}/upgrade-state/active-slot" ]] && chmod 660 "${BOXMUNGE_ROOT}/upgrade-state/active-slot"
    [[ -f "${BOXMUNGE_ROOT}/upgrade-state/blocklist.json" ]] && chmod 660 "${BOXMUNGE_ROOT}/upgrade-state/blocklist.json"
fi

# Ensure caddy/sites perms: 775 root:deploy so deploy can write generated
# configs (group) AND the caddy container can traverse the dir (other +x).
# Idempotent — fixes existing installs where sites was 770 or 755.
if [[ -d "${BOXMUNGE_ROOT}/caddy/sites" ]]; then
    chown root:deploy "${BOXMUNGE_ROOT}/caddy/sites"
    chmod 775 "${BOXMUNGE_ROOT}/caddy/sites"
fi

# Ensure maintenance dir exists and is mounted into Caddy. Used by the
# pause/resume feature (v0.4) — Caddy serves a static 503 page from here
# while a project is paused. Idempotent.
mkdir -p "${BOXMUNGE_ROOT}/caddy/maintenance"
chown root:deploy "${BOXMUNGE_ROOT}/caddy/maintenance"
chmod 755 "${BOXMUNGE_ROOT}/caddy/maintenance"
if [[ -f "${SCRIPT_DIR}/caddy/maintenance/index.html" ]]; then
    cp "${SCRIPT_DIR}/caddy/maintenance/index.html" \
        "${BOXMUNGE_ROOT}/caddy/maintenance/index.html"
    chmod 644 "${BOXMUNGE_ROOT}/caddy/maintenance/index.html"
fi

# Refresh system Caddy compose so existing installs pick up new mounts
# (e.g., the v0.4 maintenance bind-mount). If the compose file actually
# changed, restart Caddy so the new mount takes effect.
if [[ -f "${SCRIPT_DIR}/caddy/compose.yml" ]]; then
    CADDY_COMPOSE_CHANGED=0
    if ! cmp -s "${SCRIPT_DIR}/caddy/compose.yml" "${BOXMUNGE_ROOT}/caddy/compose.yml"; then
        CADDY_COMPOSE_CHANGED=1
    fi
    cp "${SCRIPT_DIR}/caddy/compose.yml" "${BOXMUNGE_ROOT}/caddy/compose.yml"
    chown root:deploy "${BOXMUNGE_ROOT}/caddy/compose.yml"
    chmod 640 "${BOXMUNGE_ROOT}/caddy/compose.yml"
    if [[ "${CADDY_COMPOSE_CHANGED}" -eq 1 ]] && docker inspect boxmunge-caddy >/dev/null 2>&1; then
        docker compose -f "${BOXMUNGE_ROOT}/caddy/compose.yml" up -d
    fi
fi

# Ensure stashes dir exists and is writable by deploy (group). Stash files
# are created by deploy during upgrade flows; the dir itself is root-owned
# so deploy cannot rename/delete the dir, only files inside.
# Idempotent — fixes existing v0.3.x installs where stashes was root:root 700.
mkdir -p "${BOXMUNGE_ROOT}/stashes"
chown root:deploy "${BOXMUNGE_ROOT}/stashes"
chmod 770 "${BOXMUNGE_ROOT}/stashes"

# Ensure backup.key is readable by deploy (group). Manual `boxmunge backup`
# from the deploy shell and pre-deploy snapshots from `prod-deploy` need to
# read the age recipient out of this file. Idempotent — fixes hosts where
# the v0.1.x → v0.1.2 migration left it as root:root 640.
if [[ -f "${BOXMUNGE_ROOT}/config/backup.key" ]]; then
    chown root:deploy "${BOXMUNGE_ROOT}/config/backup.key"
    chmod 640 "${BOXMUNGE_ROOT}/config/backup.key"
fi
"${BOXMUNGE_ROOT}/env-active/bin/pip" install --quiet --upgrade pip
"${BOXMUNGE_ROOT}/env-active/bin/pip" install --quiet "${SCRIPT_DIR}[tui]"

# pip install as root leaves root-owned build artifacts in the source directory.
# Clean them up so the deploy user can rm the extraction dir on future upgrades.
rm -rf "${SCRIPT_DIR}/build" "${SCRIPT_DIR}/src/"*.egg-info

# ---------------------------------------------------------------------------
# CLI wrappers (use env-active, not a fixed venv path)
# ---------------------------------------------------------------------------
cat > "${BOXMUNGE_ROOT}/bin/boxmunge" <<'WRAPPER'
#!/usr/bin/env bash
# The pip-installed entry point is named boxmunge-server (per pyproject.toml
# project.scripts). The user-facing command is boxmunge — this wrapper
# bridges the two.
exec /opt/boxmunge/env-active/bin/boxmunge-server "$@"
WRAPPER
chmod 755 "${BOXMUNGE_ROOT}/bin/boxmunge"

cat > "${BOXMUNGE_ROOT}/bin/boxmunge-server" <<'WRAPPER'
#!/usr/bin/env bash
exec /opt/boxmunge/env-active/bin/boxmunge-server "$@"
WRAPPER
chmod 755 "${BOXMUNGE_ROOT}/bin/boxmunge-server"

cat > "${BOXMUNGE_ROOT}/bin/boxmunge-shell" <<'WRAPPER'
#!/usr/bin/env bash
exec /opt/boxmunge/env-active/bin/boxmunge-shell "$@"
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
# Modern OpenSSH (9+) routes scp through the SFTP protocol, so the Subsystem
# directive — not the login shell — decides where uploads go. The wrapper
# only runs uploads through reception if sshd actually invokes it. This step
# is idempotent and runs on every install/upgrade so the wiring cannot drift.
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

# ---------------------------------------------------------------------------
# Install the boxmunge-upgrade shim (orchestrates auto-updates)
# ---------------------------------------------------------------------------
cp "${SCRIPT_DIR}/scripts/boxmunge-upgrade" "${BOXMUNGE_ROOT}/bin/boxmunge-upgrade"
chmod 755 "${BOXMUNGE_ROOT}/bin/boxmunge-upgrade"

# Symlink into /usr/local/bin so boxmunge works in non-interactive SSH sessions
ln -sf "${BOXMUNGE_ROOT}/bin/boxmunge" /usr/local/bin/boxmunge
ln -sf "${BOXMUNGE_ROOT}/bin/boxmunge-server" /usr/local/bin/boxmunge-server

# ---------------------------------------------------------------------------
# On-server documentation
# ---------------------------------------------------------------------------
if [[ -d "${SCRIPT_DIR}/on-server" ]]; then
    mkdir -p "${BOXMUNGE_ROOT}/docs"
    cp "${SCRIPT_DIR}/on-server/"*.md "${BOXMUNGE_ROOT}/docs/"
    chmod 644 "${BOXMUNGE_ROOT}/docs/"*.md
fi

# ---------------------------------------------------------------------------
# Canary project template (used by `boxmunge self-test`)
#
# self_test_cmd._canary_project_path() looks at /opt/boxmunge/canary first.
# If we don't ship it, self-test errors with "Canary project not found"
# on every real install.
# ---------------------------------------------------------------------------
if [[ -d "${SCRIPT_DIR}/canary" ]]; then
    rm -rf "${BOXMUNGE_ROOT}/canary"
    cp -r "${SCRIPT_DIR}/canary" "${BOXMUNGE_ROOT}/canary"
    chown -R root:root "${BOXMUNGE_ROOT}/canary"
fi

# ---------------------------------------------------------------------------
# Systemd units
# ---------------------------------------------------------------------------
echo ""
echo "========================================================"
echo "  Installing systemd units"
echo "========================================================"

cp "${SCRIPT_DIR}/systemd/"*.service /etc/systemd/system/
cp "${SCRIPT_DIR}/systemd/"*.timer   /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now \
    boxmunge-backup.timer \
    boxmunge-health.timer \
    boxmunge-backup-sync.timer \
    boxmunge-auto-update.timer \
    boxmunge-container-update.timer \
    boxmunge-cve-scan.timer

# ---------------------------------------------------------------------------
# Sudoers: allow deploy to invoke the upgrade shim (single binary scope).
# This lets `boxmunge upgrade` from the deploy shell route to the root-context
# shim that handles stash + venv swap + probation properly. Same root of trust
# as supervisor (deploy and supervisor share SSH keys).
# ---------------------------------------------------------------------------
SUDOERS_FILE="/etc/sudoers.d/boxmunge-deploy"
SUDOERS_RULE="deploy ALL=(root) NOPASSWD: /opt/boxmunge/bin/boxmunge-upgrade"
if [[ ! -f "${SUDOERS_FILE}" ]] || ! grep -qF "${SUDOERS_RULE}" "${SUDOERS_FILE}"; then
    echo "${SUDOERS_RULE}" > "${SUDOERS_FILE}"
    chmod 440 "${SUDOERS_FILE}"
    chown root:root "${SUDOERS_FILE}"
    visudo -cqf "${SUDOERS_FILE}" || {
        rm -f "${SUDOERS_FILE}"
        echo "ERROR: sudoers rule failed validation; not installed" >&2
        exit 1
    }
fi

# ---------------------------------------------------------------------------
# Record installed version (read by boxmunge auto-update to decide if a
# new release is available). Package is named boxmunge-server in pyproject.
# ---------------------------------------------------------------------------
INSTALLED_VERSION="$("${BOXMUNGE_ROOT}/env-active/bin/pip" show boxmunge-server 2>/dev/null \
    | grep '^Version:' | cut -d' ' -f2 || echo "unknown")"

if [[ "${INSTALLED_VERSION}" != "unknown" ]]; then
    echo "${INSTALLED_VERSION}" > "${BOXMUNGE_ROOT}/config/version"
fi

echo ""
echo "========================================================"
echo "  boxmunge ${INSTALLED_VERSION} installed successfully"
echo "========================================================"
