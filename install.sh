#!/usr/bin/env bash
# boxmunge install.sh
# Installs boxmunge on a Debian or Ubuntu VPS.
#
# Fresh install (runs full system bootstrap first):
#   sudo bash install.sh --hostname HOST --email EMAIL --ssh-key KEY [--ssh-port PORT]
#
# Upgrade (SSH in as deploy user, elevate with sudo):
#   sudo bash install.sh
#
# From the upgrade shim (system pieces only; the shim installs the package
# into the standby venv and records the version itself):
#   bash install.sh --upgrade-shim

set -euo pipefail

BOXMUNGE_ROOT="/opt/boxmunge"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# During an upgrade env-active is still the PREVIOUS release's venv, the one a
# rollback returns to. Installing the new package into it would leave nothing
# to roll back to, so the shim passes --upgrade-shim and keeps venvs to itself.
FROM_UPGRADE_SHIM=0
if [[ "${1:-}" == "--upgrade-shim" ]]; then
    FROM_UPGRADE_SHIM=1
    shift
fi

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

# The upgrade shim a release ships is built self-contained (scripts/build-shim.py
# via `make bundle`). The unbuilt source shim needs scripts/boxmunge-upgrade.d/
# beside it and would refuse every command once installed into bin/.
if grep -q '^# >>> boxmunge-upgrade.d:' "${SCRIPT_DIR}/scripts/boxmunge-upgrade"; then
    echo "ERROR: ${SCRIPT_DIR}/scripts/boxmunge-upgrade is the unbuilt source shim." >&2
    echo "       Install from a release bundle (boxmunge-install.sh, or \`make bundle\`), not a source checkout." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Docker Compose version.
#
# boxmunge resolves user compose with `config --no-env-resolution`, which
# Compose accepts from 2.35.0 (2.34 and older: "unknown flag"). That also
# covers secrets' single-quoted env-file values with \' for a quote, which
# Compose reads literally from 2.24 on. Keep in step with
# MIN_COMPOSE_VERSION in src/boxmunge/compose_version.py. An upgrade checks
# before anything is changed; a fresh install right after the bootstrap has
# installed Docker.
# ---------------------------------------------------------------------------
MIN_COMPOSE_VERSION="2.35.0"
# Same rule as compose_version.py: trim ASCII whitespace, then the whole
# output must be one version with an optional packaging suffix; anything
# else is reported as unreadable, never guessed at.
require_compose_version() {
    local ws=$' \t\r\n\v\f' raw found
    if ! raw="$(docker compose version --short 2>/dev/null)"; then
        echo "ERROR: 'docker compose version --short' failed. Install" \
             "docker-compose-plugin ${MIN_COMPOSE_VERSION} or newer from Docker's apt repository." >&2
        exit 1
    fi
    found="${raw#"${raw%%[!${ws}]*}"}"
    found="${found%"${found##*[!${ws}]}"}"
    local re='^v?([0-9]+)\.([0-9]+)\.([0-9]+)([-+][^'"${ws}"']*)?$'
    if [[ ! "${found}" =~ ${re} ]]; then
        echo "ERROR: could not read the Docker Compose version from" \
             "'docker compose version --short', which printed: $(printf '%q' "${raw}")" >&2
        exit 1
    fi
    local have=( "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" )
    local want=( ${MIN_COMPOSE_VERSION//./ } ) i
    for i in 0 1 2; do
        (( 10#${have[i]} > 10#${want[i]} )) && return 0
        if (( 10#${have[i]} < 10#${want[i]} )); then
            echo "ERROR: Docker Compose ${found} is older than ${MIN_COMPOSE_VERSION}," \
                 "which boxmunge needs to pass secrets to containers unchanged." \
                 "Upgrade it: apt-get install --only-upgrade docker-compose-plugin" >&2
            exit 1
        fi
    done
}
if [[ -f "${BOXMUNGE_ROOT}/config/boxmunge.yml" ]]; then
    require_compose_version
fi

# ---------------------------------------------------------------------------
# Dead CrowdSec apt source.
#
# Earlier bootstraps added CrowdSec's packagecloud repository, which has no
# Debian 13 (trixie) release: its apt source makes every `apt-get update` on
# the host fail, including the ones this installer runs. CrowdSec comes from
# Debian's own archive, so on trixie the source and its key are removed.
# Runs before anything below calls apt-get.
# ---------------------------------------------------------------------------
remove_dead_crowdsec_repo() {
    local list=/etc/apt/sources.list.d/crowdsec_crowdsec.list
    [[ -f "${list}" ]] || return 0
    grep -q '^VERSION_CODENAME=trixie$' /etc/os-release || return 0
    echo "  Removing CrowdSec's packagecloud apt source (it has no trixie release)"
    rm -f "${list}" /etc/apt/keyrings/crowdsec_crowdsec-archive-keyring.gpg
}
remove_dead_crowdsec_repo

# ---------------------------------------------------------------------------
# Broken unattended-upgrades origins.
#
# Earlier bootstraps put an Origins-Pattern match inside the legacy
# Allowed-Origins list, which crashes unattended-upgrade on every run, so
# those hosts never installed an OS security update. A file still carrying
# that exact line is replaced with the bundled config; one an operator has
# edited since is left alone (`health` reports the failing runs).
# ---------------------------------------------------------------------------
repair_unattended_origins() {
    local conf=/etc/apt/apt.conf.d/50unattended-upgrades
    [[ -f "${conf}" ]] || return 0
    grep -q '^Unattended-Upgrade::Allowed-Origins {$' "${conf}" || return 0
    grep -q '^    "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";$' \
        "${conf}" || return 0
    echo "  Repairing ${conf}: unattended-upgrade has been crashing on its origins list"
    install -m 0644 "${SCRIPT_DIR}/bootstrap/50unattended-upgrades-debian" "${conf}"
}
repair_unattended_origins

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
#
# Idempotency:
#   The presence-on-PATH check is paired with a dpkg-query check on the
#   package state. If the binary exists but dpkg's recorded status is not
#   "installed" (e.g. partial install, manual binary drop into /usr/local,
#   or `apt remove` leaving config residue), the install path is re-entered
#   and apt-get install is run with --reinstall to recover.
# ---------------------------------------------------------------------------
install_trivy() {
    if command -v trivy >/dev/null 2>&1 \
       && dpkg-query -W -f='${db:Status-Status}' trivy 2>/dev/null \
            | grep -q "^installed$"; then
        local installed_version
        installed_version="$(trivy --version 2>/dev/null | head -1 \
            | awk '{print $2}' || echo unknown)"
        echo "  Trivy already installed (version=${installed_version}); skipping reinstall"
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
    # --reinstall handles the dpkg-leftover case where a prior `apt remove`
    # left metadata behind: a plain `install` would no-op if dpkg considers
    # the package already present in some state.
    DEBIAN_FRONTEND=noninteractive apt-get install -y --reinstall trivy

    local installed_version
    installed_version="$(trivy --version 2>/dev/null | head -1 \
        | awk '{print $2}' || echo unknown)"
    echo "  Trivy installed (version=${installed_version})"
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
    require_compose_version
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

# The Caddy site journal (boxmunge.caddy_journal) is written by deploy-run
# deploys, but caddy/ is root:deploy 750, so deploy cannot create it: the
# first site write on a box without it would fail. Idempotent.
install -d -m 700 -o deploy -g deploy "${BOXMUNGE_ROOT}/caddy/.site-journal"

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

# Caddy logs access to stdout, not to the caddy/logs mount the compose file
# below no longer has: fix site configs before Caddy is recreated on it.
bash "${SCRIPT_DIR}/bootstrap/caddy-access-log.sh" sites

# Refresh system Caddy compose so existing installs pick up new mounts
# (e.g., the v0.4 maintenance bind-mount). Compose recreates Caddy only when
# its definition changed; asking every time also finishes a recreate that an
# earlier run copied the file for but did not get to.
if [[ -f "${SCRIPT_DIR}/caddy/compose.yml" ]]; then
    cp "${SCRIPT_DIR}/caddy/compose.yml" "${BOXMUNGE_ROOT}/caddy/compose.yml"
    chown root:deploy "${BOXMUNGE_ROOT}/caddy/compose.yml"
    chmod 640 "${BOXMUNGE_ROOT}/caddy/compose.yml"
    if docker inspect boxmunge-caddy >/dev/null 2>&1; then
        docker compose -f "${BOXMUNGE_ROOT}/caddy/compose.yml" up -d
    fi
fi
bash "${SCRIPT_DIR}/bootstrap/caddy-access-log.sh" retire

# CrowdSec reads Caddy's stdout through Docker; verified after the restart.
if command -v cscli >/dev/null 2>&1; then
    BOXMUNGE_ROOT="${BOXMUNGE_ROOT}" bash "${SCRIPT_DIR}/bootstrap/crowdsec-acquis.sh"
else
    echo "  CrowdSec is not installed (--no-crowdsec): nothing watches Caddy's access log"
fi

# rclone config for off-site backup-sync. Mounted read-only into the
# boxmunge-system container at /config/rclone (a directory mount, so editing
# rclone.conf in place is seen without recreating the container). An empty
# file is a valid rclone config; the operator adds remotes to it.
mkdir -p "${BOXMUNGE_ROOT}/config/rclone"
chown root:deploy "${BOXMUNGE_ROOT}/config/rclone"
chmod 750 "${BOXMUNGE_ROOT}/config/rclone"
if [[ ! -f "${BOXMUNGE_ROOT}/config/rclone/rclone.conf" ]]; then
    install -m 640 -o root -g deploy /dev/null "${BOXMUNGE_ROOT}/config/rclone/rclone.conf"
fi

# Build + (re)start the boxmunge-system container — isolation for age/rclone
# (blast-radius containment). There is no host fallback: while the container
# is absent, backups, restores and backup-sync fail loudly. A transient
# build/network failure still must not block an upgrade, so warn and carry
# on. Rebuild (tagging boxmunge.invalid/system/system, the data helper's image) only when the definition changed or the container isn't
# running, mirroring the caddy block.
if [[ -d "${SCRIPT_DIR}/system" ]]; then
    SYSTEM_CHANGED=0
    mkdir -p "${BOXMUNGE_ROOT}/system"
    # The container runs as the deploy user so it can read the 0600 backup
    # temp files and the root:deploy backup key (compose.yml `user:`).
    printf 'BOXMUNGE_UID=%s\nBOXMUNGE_GID=%s\nBOXMUNGE_CONFIG=%s\nBOXMUNGE_PROJECTS=%s\n' \
        "$(id -u deploy)" "$(id -g deploy)" \
        "${BOXMUNGE_ROOT}/config" "${BOXMUNGE_ROOT}/projects" \
        > "${BOXMUNGE_ROOT}/system/.env.next"
    for f in Dockerfile compose.yml; do
        if ! cmp -s "${SCRIPT_DIR}/system/$f" "${BOXMUNGE_ROOT}/system/$f" 2>/dev/null; then
            SYSTEM_CHANGED=1
        fi
        cp "${SCRIPT_DIR}/system/$f" "${BOXMUNGE_ROOT}/system/$f"
    done
    if ! cmp -s "${BOXMUNGE_ROOT}/system/.env.next" "${BOXMUNGE_ROOT}/system/.env" 2>/dev/null; then
        SYSTEM_CHANGED=1
    fi
    mv "${BOXMUNGE_ROOT}/system/.env.next" "${BOXMUNGE_ROOT}/system/.env"
    chown -R root:root "${BOXMUNGE_ROOT}/system"
    if [[ "${SYSTEM_CHANGED}" -eq 1 ]] || ! docker inspect boxmunge-system >/dev/null 2>&1; then
        if ! docker compose -f "${BOXMUNGE_ROOT}/system/compose.yml" up -d --build; then
            echo "WARNING: boxmunge-system container build failed. Backups," \
                 "restores and backup-sync will FAIL until it runs. Re-run" \
                 "install.sh to retry." >&2
        fi
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
# Dependencies come only from the hash-pinned requirements files in the signed
# bundle; the package itself installs without resolving anything further and
# builds with the hash-pinned backend already in the venv. The venv's own pip
# (from the distro's python3-venv) is used as is: upgrading it would be one
# more unpinned download. MCP is always installed: it is how agents operate
# the box, and every upgrade installs the same files into the new slot.
if [[ "${FROM_UPGRADE_SHIM}" -eq 0 ]]; then
    "${BOXMUNGE_ROOT}/env-active/bin/pip" install --quiet --no-cache-dir --require-hashes \
        -r "${SCRIPT_DIR}/requirements-build.txt" -r "${SCRIPT_DIR}/requirements-tui.txt" \
        -r "${SCRIPT_DIR}/requirements-mcp.txt"
    "${BOXMUNGE_ROOT}/env-active/bin/pip" install --quiet --no-cache-dir --no-deps --no-build-isolation "${SCRIPT_DIR}"
fi

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
# The wrapper refuses SFTP for deploy (sftp-server cannot be confined to the
# inbox without chrooting every deploy session, and unconfined it exposes
# everything deploy can read and write) and execs the real sftp-server for
# everyone else. deploy uploads with legacy scp (`scp -O`), which the
# restricted shell receives through `scp -t`. Idempotent; runs on every
# install/upgrade so the wiring cannot drift.
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

# Key-only logins and no forwarding, as a drop-in that wins over cloud-init's
# (the script says why). Every install and upgrade re-applies it, so boxes
# bootstrapped before it get it too; it fails the install if sshd would not
# enforce it.
DEPLOY_USER=deploy bash "${SCRIPT_DIR}/bootstrap/sshd-hardening.sh"

# ---------------------------------------------------------------------------
# Install the boxmunge-upgrade shim (orchestrates auto-updates)
#
# The bundle's shim is built self-contained (scripts/build-shim.py). A
# pre-release build of this change installed its libraries separately into
# bin/boxmunge-upgrade.d/; nothing reads that any more.
# ---------------------------------------------------------------------------
cp "${SCRIPT_DIR}/scripts/boxmunge-upgrade" "${BOXMUNGE_ROOT}/bin/boxmunge-upgrade"
chmod 755 "${BOXMUNGE_ROOT}/bin/boxmunge-upgrade"
rm -rf "${BOXMUNGE_ROOT}/bin/boxmunge-upgrade.d"

# Symlink into /usr/local/bin so boxmunge works in non-interactive SSH sessions
ln -sf "${BOXMUNGE_ROOT}/bin/boxmunge" /usr/local/bin/boxmunge
ln -sf "${BOXMUNGE_ROOT}/bin/boxmunge-server" /usr/local/bin/boxmunge-server

# ---------------------------------------------------------------------------
# On-server documentation
# ---------------------------------------------------------------------------
# The shim replaces docs/ as a whole (atomic symlink swap), so docs removed
# from the release disappear. Every upgrade does the same from the release
# it installs, and a rollback restores the previous release's docs.
"${BOXMUNGE_ROOT}/bin/boxmunge-upgrade" install-docs "${SCRIPT_DIR}/on-server"

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
# Sudoers: deploy may run exactly `boxmunge-upgrade auto` and
# `boxmunge-upgrade target <version>` as root, so `upgrade` from the deploy
# shell reaches the shim that handles stash + venv swap + probation. The rule
# text lives in the shim (install-sudoers), which validates it with visudo
# before replacing /etc/sudoers.d/boxmunge-deploy. Every upgrade rewrites it
# too, so a box carrying an older, wider rule is tightened on upgrade.
# ---------------------------------------------------------------------------
"${BOXMUNGE_ROOT}/bin/boxmunge-upgrade" install-sudoers

# ---------------------------------------------------------------------------
# Record installed version (read by boxmunge auto-update to decide if a
# new release is available). Package is named boxmunge-server in pyproject.
# ---------------------------------------------------------------------------
INSTALLED_VERSION="$("${BOXMUNGE_ROOT}/env-active/bin/pip" show boxmunge-server 2>/dev/null \
    | grep '^Version:' | cut -d' ' -f2 || echo "unknown")"

if [[ "${INSTALLED_VERSION}" != "unknown" && "${FROM_UPGRADE_SHIM}" -eq 0 ]]; then
    echo "${INSTALLED_VERSION}" > "${BOXMUNGE_ROOT}/config/version"
fi

# ---------------------------------------------------------------------------
# Record the installer fingerprint (sha256 of this script as it was applied)
# so the upgrade shim can detect when a future release ships an install.sh
# that differs from the one this host already ran — and re-invoke install.sh
# automatically before flipping to the new venv. Without this, system-level
# changes (new apt packages, new systemd units, install.sh-only migrations)
# silently require a manual `bash boxmunge-install.sh` after every upgrade.
# Written last so a partial install (which exits earlier under `set -e`)
# leaves the prior fingerprint in place — the shim will then re-run on the
# next upgrade attempt.
# ---------------------------------------------------------------------------
INSTALLER_HASH_FILE="${BOXMUNGE_ROOT}/state/installer.sha256"
mkdir -p "$(dirname "${INSTALLER_HASH_FILE}")"
sha256sum "${SCRIPT_DIR}/install.sh" 2>/dev/null \
    | awk '{print $1}' > "${INSTALLER_HASH_FILE}.tmp"
mv -f "${INSTALLER_HASH_FILE}.tmp" "${INSTALLER_HASH_FILE}"
chown root:deploy "${INSTALLER_HASH_FILE}" 2>/dev/null || true
chmod 0644 "${INSTALLER_HASH_FILE}"

echo ""
echo "========================================================"
echo "  boxmunge ${INSTALLED_VERSION} installed successfully"
echo "========================================================"
