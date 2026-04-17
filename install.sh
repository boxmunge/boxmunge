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
# Pre-flight
# ---------------------------------------------------------------------------
if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

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
    chmod 640 "${KEY_FILE}"
    PUBKEY="$(age-keygen -y "${KEY_FILE}")"
    echo "  New public key: ${PUBKEY}"
    echo "  Old passphrase key saved as: ${KEY_FILE}.old-passphrase"
    echo "  NOTE: Existing backups used the old passphrase."
    echo "        New backups will use the age identity."
fi

# ---------------------------------------------------------------------------
# Install boxmunge Python package into isolated venv
# ---------------------------------------------------------------------------
echo ""
echo "========================================================"
echo "  Installing boxmunge package"
echo "========================================================"

python3 -m venv "${BOXMUNGE_ROOT}/venv"
"${BOXMUNGE_ROOT}/venv/bin/pip" install --quiet --upgrade pip
"${BOXMUNGE_ROOT}/venv/bin/pip" install --quiet "${SCRIPT_DIR}[tui]"

# pip install as root leaves root-owned build artifacts in the source directory.
# Clean them up so the deploy user can rm the extraction dir on future upgrades.
rm -rf "${SCRIPT_DIR}/build" "${SCRIPT_DIR}/src/"*.egg-info

# ---------------------------------------------------------------------------
# CLI wrapper (uses venv, not system Python)
# ---------------------------------------------------------------------------
cat > "${BOXMUNGE_ROOT}/bin/boxmunge" <<'WRAPPER'
#!/usr/bin/env bash
exec /opt/boxmunge/venv/bin/boxmunge "$@"
WRAPPER
chmod 755 "${BOXMUNGE_ROOT}/bin/boxmunge"

cat > "${BOXMUNGE_ROOT}/bin/boxmunge-server" <<'WRAPPER'
#!/usr/bin/env bash
exec /opt/boxmunge/venv/bin/boxmunge-server "$@"
WRAPPER
chmod 755 "${BOXMUNGE_ROOT}/bin/boxmunge-server"

cat > "${BOXMUNGE_ROOT}/bin/boxmunge-shell" <<'WRAPPER'
#!/usr/bin/env bash
exec /opt/boxmunge/venv/bin/boxmunge-shell "$@"
WRAPPER
chmod 755 "${BOXMUNGE_ROOT}/bin/boxmunge-shell"

cat > "${BOXMUNGE_ROOT}/bin/boxmunge-sftp" <<'WRAPPER'
#!/usr/bin/env bash
# SFTP subsystem handler for boxmunge.
# For the deploy user: runs sftp-server normally (files land in ~deploy/),
# then moves received files through the reception handler into the inbox.
# For other users: passes through to the real sftp-server.
DEPLOY_HOME="/home/deploy"

if [ "$(id -un)" = "deploy" ]; then
    # Snapshot existing files in home dir before sftp
    before=$(ls -1 "$DEPLOY_HOME" 2>/dev/null)

    /usr/lib/openssh/sftp-server "$@"
    RC=$?

    # Find new files that weren't there before
    after=$(ls -1 "$DEPLOY_HOME" 2>/dev/null)
    new_files=$(comm -13 <(echo "$before") <(echo "$after"))

    for fname in $new_files; do
        f="$DEPLOY_HOME/$fname"
        [ -f "$f" ] || continue
        /opt/boxmunge/venv/bin/python3 -c "
from boxmunge.reception import receive_bundle
from boxmunge.paths import BoxPaths
from pathlib import Path
import sys
try:
    dest = receive_bundle(Path('$f'), BoxPaths())
    print(f'Received: {dest.name}', file=sys.stderr)
except ValueError as e:
    print(f'Upload rejected: {e}', file=sys.stderr)
    Path('$f').unlink(missing_ok=True)
"
    done
    exit $RC
else
    exec /usr/lib/openssh/sftp-server "$@"
fi
WRAPPER
chmod 755 "${BOXMUNGE_ROOT}/bin/boxmunge-sftp"

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
    boxmunge-backup-sync.timer

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------
INSTALLED_VERSION="$("${BOXMUNGE_ROOT}/venv/bin/pip" show boxmunge 2>/dev/null \
    | grep '^Version:' | cut -d' ' -f2 || echo "unknown")"

echo ""
echo "========================================================"
echo "  boxmunge ${INSTALLED_VERSION} installed successfully"
echo "========================================================"
