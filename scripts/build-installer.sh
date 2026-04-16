#!/usr/bin/env bash
# Build a self-extracting boxmunge installer.
#
# Produces dist/boxmunge-install.sh — a single file that contains the
# entire boxmunge bundle as a base64-encoded payload. Copy it to the
# server and run it. No scp of tarballs, no extraction steps.
#
# Usage:
#   ./scripts/build-installer.sh
#   scp dist/boxmunge-install.sh root@box:
#   ssh root@box "bash boxmunge-install.sh --hostname box.example.com --email admin@example.com --ssh-key 'ssh-ed25519 AAAA...'"
#
# For upgrades:
#   scp dist/boxmunge-install.sh supervisor@box:
#   ssh supervisor@box "sudo bash boxmunge-install.sh"

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

# Build the bundle first
make bundle

BUNDLE="dist/boxmunge-$(python3 -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])"  ).tar.gz"

if [[ ! -f "$BUNDLE" ]]; then
    echo "ERROR: Bundle not found at $BUNDLE" >&2
    exit 1
fi

INSTALLER="dist/boxmunge-install.sh"
BUNDLE_SIZE="$(du -h "$BUNDLE" | cut -f1)"
PAYLOAD="$(base64 < "$BUNDLE")"

cat > "$INSTALLER" <<'HEADER'
#!/usr/bin/env bash
# boxmunge self-extracting installer
# Generated — do not edit. Rebuild with: ./scripts/build-installer.sh
#
# Fresh install:
#   sudo bash boxmunge-install.sh --hostname HOST --email EMAIL --ssh-key KEY [--ssh-port PORT]
#
# Upgrade:
#   sudo bash boxmunge-install.sh
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "Extracting boxmunge..."
# Decode the embedded payload and extract
sed '1,/^__PAYLOAD__$/d' "$0" | base64 -d | tar xz -C "$TMPDIR"

cd "$TMPDIR/boxmunge"
bash install.sh "$@"
exit 0

__PAYLOAD__
HEADER

echo "$PAYLOAD" >> "$INSTALLER"
chmod +x "$INSTALLER"

INSTALLER_SIZE="$(du -h "$INSTALLER" | cut -f1)"
echo "Built $INSTALLER (${INSTALLER_SIZE}, bundle was ${BUNDLE_SIZE})"
echo ""
echo "Deploy:"
echo "  scp $INSTALLER root@box:"
echo "  ssh root@box \"bash boxmunge-install.sh --hostname box.example.com --email admin@example.com --ssh-key 'ssh-ed25519 ...'\""
echo ""
echo "Upgrade:"
echo "  scp $INSTALLER supervisor@box:"
echo "  ssh supervisor@box \"sudo bash boxmunge-install.sh\""
