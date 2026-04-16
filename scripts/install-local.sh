#!/usr/bin/env bash
# Install boxmunge locally for bundle building.
# Creates an isolated venv and symlinks to ~/bin/boxmunge.
set -euo pipefail

VENV_DIR="$HOME/.local/share/boxmunge-venv"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="$HOME/bin"

echo "Installing boxmunge from $REPO_DIR"

# Create or reuse venv
if [ ! -d "$VENV_DIR" ]; then
    echo "  Creating venv at $VENV_DIR"
    python3 -m venv "$VENV_DIR"
fi

# Install/upgrade
echo "  Installing package..."
"$VENV_DIR/bin/pip" install --quiet --upgrade "$REPO_DIR"

# Symlink
mkdir -p "$BIN_DIR"
ln -sf "$VENV_DIR/bin/boxmunge" "$BIN_DIR/boxmunge"

echo "  Installed: $(boxmunge help 2>&1 | head -1)"
echo ""
echo "Done. 'boxmunge' is available at $BIN_DIR/boxmunge"
echo "Test with: boxmunge bundle --validate <project-dir>"
