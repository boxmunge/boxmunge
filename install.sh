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
# From the upgrade shim (system pieces and the standby venv's hash-pinned
# dependencies; the shim installs the package and records the version itself):
#   bash install.sh --upgrade-shim

set -euo pipefail

BOXMUNGE_ROOT="/opt/boxmunge"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# During an upgrade env-active is still the PREVIOUS release's venv, the one a
# rollback returns to, so a run by the shim leaves it alone. Shims up to 0.10.0
# pass no --upgrade-shim; after the pre-flight, run-by-old-shim.sh spots them.
FROM_UPGRADE_SHIM=0
if [[ "${1:-}" == "--upgrade-shim" ]]; then
    FROM_UPGRADE_SHIM=1
    shift
fi

# shellcheck source=bootstrap/cosign.sh
source "${SCRIPT_DIR}/bootstrap/cosign.sh"

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------
if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

# cosign (bootstrap/cosign.sh) and age and rclone (system/Dockerfile) are
# pinned for amd64 and arm64 only; on any other CPU the install would fail
# halfway or leave backups unable to run.
HOST_ARCH="$(dpkg --print-architecture)"
if ! cosign_sha256 "${HOST_ARCH}" >/dev/null; then
    echo "ERROR: boxmunge supports amd64 (x86_64) and arm64 (aarch64) hosts;" \
         "this one is ${HOST_ARCH}. Install it on a Debian 13 VPS with one of those CPUs." >&2
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
[[ "${FROM_UPGRADE_SHIM}" -eq 1 ]] || FROM_UPGRADE_SHIM="$(BOXMUNGE_ROOT="${BOXMUNGE_ROOT}" bash "${SCRIPT_DIR}/bootstrap/run-by-old-shim.sh")"
command -v python3 >/dev/null && bash "${SCRIPT_DIR}/bootstrap/python-floor.sh"

# Docker Compose 2.35.0 or newer (bootstrap/compose-version.sh): an upgrade
# checks before anything is changed, a fresh install after the bootstrap.
if [[ -f "${BOXMUNGE_ROOT}/config/boxmunge.yml" ]]; then
    bash "${SCRIPT_DIR}/bootstrap/compose-version.sh"
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
    # shellcheck disable=SC2016  # the file's own literal ${distro_codename}
    grep -q '^    "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";$' \
        "${conf}" || return 0
    echo "  Repairing ${conf}: unattended-upgrade has been crashing on its origins list"
    install -m 0644 "${SCRIPT_DIR}/bootstrap/50unattended-upgrades-debian" "${conf}"
}
repair_unattended_origins

# cosign/Trivy run before init-host.sh installs gnupg, which cloud images lack.
ensure_install_prereqs() {
    local missing=(); command -v curl >/dev/null 2>&1 || missing+=(curl)
    command -v gpg >/dev/null 2>&1 || missing+=(gnupg)
    dpkg-query -W -f='${db:Status-Status}' ca-certificates 2>/dev/null | grep -q "^installed$" || missing+=(ca-certificates)
    [[ ${#missing[@]} -eq 0 ]] && return 0
    echo "  Installing prerequisites for cosign/Trivy: ${missing[*]}"
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}"
}
ensure_install_prereqs

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
        curl -sSLf --connect-timeout 30 --max-time 120 https://aquasecurity.github.io/trivy-repo/deb/public.key \
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
# Fatal on failure: the upgrade shim would refuse every future release.
install_cosign "${HOST_ARCH}"

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
    bash "${SCRIPT_DIR}/bootstrap/compose-version.sh"
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

# Ensure upgrade-state perms allow deploy access (idempotent). Not chown -R:
# that left probation.json unreadable to deploy (see the script).
if [[ -d "${BOXMUNGE_ROOT}/upgrade-state" ]]; then
    chown root:deploy "${BOXMUNGE_ROOT}/upgrade-state"
    chmod 770 "${BOXMUNGE_ROOT}/upgrade-state"
    BOXMUNGE_ROOT="${BOXMUNGE_ROOT}" bash "${SCRIPT_DIR}/bootstrap/upgrade-state-perms.sh"
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

# Steps that are recorded rather than fatal when they fail: the rest of the
# install carries on, and fail_if_incomplete stops a fresh install or an
# operator's re-run at the end, naming each. Run by the upgrade shim they only
# warn: the shim blocklists a release on any install.sh failure, which for a
# transient download or pull error would hold the release's fixes off the
# box while the previous container keeps running (`health` and `doctor` say
# so). Either way the installer fingerprint is left unrecorded, so the next
# upgrade runs install.sh, and these steps, again.
INCOMPLETE=""
# note_incomplete <message words...>
note_incomplete() {
    INCOMPLETE="${INCOMPLETE}  - $*"$'\n'
    echo "WARNING: $*" >&2
}

# Caddy logs access to stdout, not to the caddy/logs mount the compose file
# below no longer has: fix site configs before Caddy is recreated on it.
bash "${SCRIPT_DIR}/bootstrap/caddy-access-log.sh" sites

# Refresh system Caddy compose so existing installs pick up new mounts
# (e.g., the v0.4 maintenance bind-mount). Compose recreates Caddy only when
# its definition changed; asking every time also finishes a recreate that an
# earlier run copied the file for but did not get to.
# A failed `up` (a transient pull of the pinned image, say) is noted, and
# caddy/logs is kept: the Caddy that keeps running may still mount it.
CADDY_KEPT_OLD=0
refresh_caddy() {
    [[ -f "${SCRIPT_DIR}/caddy/compose.yml" ]] || return 0
    cp "${SCRIPT_DIR}/caddy/compose.yml" "${BOXMUNGE_ROOT}/caddy/compose.yml"
    chown root:deploy "${BOXMUNGE_ROOT}/caddy/compose.yml"
    chmod 640 "${BOXMUNGE_ROOT}/caddy/compose.yml"
    docker inspect boxmunge-caddy >/dev/null 2>&1 || return 0
    docker compose -f "${BOXMUNGE_ROOT}/caddy/compose.yml" up -d && return 0
    CADDY_KEPT_OLD=1
    note_incomplete "Caddy was not started from the new caddy/compose.yml (see above); the" \
        "previous container, if any, keeps running. Start it as supervisor once the cause is" \
        "fixed: sudo docker compose -f ${BOXMUNGE_ROOT}/caddy/compose.yml up -d"
}
refresh_caddy
[[ "${CADDY_KEPT_OLD}" -eq 1 ]] || bash "${SCRIPT_DIR}/bootstrap/caddy-access-log.sh" retire

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

# Build + (re)start the boxmunge-system container: isolation for age and
# rclone, also the data helper's image. There is no host fallback: without it
# backups, restores, backup-sync and data operations fail, so a failure is
# noted (note_incomplete) and names its fix.
SYSTEM_REBUILD="sudo docker compose -f ${BOXMUNGE_ROOT}/system/compose.yml up -d --build"
refresh_system_container() {
    local rc=0
    BOXMUNGE_ROOT="${BOXMUNGE_ROOT}" bash "${SCRIPT_DIR}/bootstrap/system-container.sh" || rc=$?
    case "${rc}" in
        0) ;;
        3) note_incomplete "the boxmunge-system container did not start (see above); its image is" \
               "current. Backups, restores and data operations need it. Start it as supervisor once" \
               "the cause is fixed: sudo docker compose -f ${BOXMUNGE_ROOT}/system/compose.yml up -d" ;;
        *) note_incomplete "the boxmunge-system image did not build (see above); the previous" \
               "container, if any, keeps running. Backups, restores and data operations need it." \
               "Rebuild it as supervisor once the cause is fixed: ${SYSTEM_REBUILD}" ;;
    esac
}
refresh_system_container

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
# Dependencies only from the bundle's hash-pinned requirements, MCP included
# (bootstrap/venv-deps.sh); the package with no further resolution, built by the
# hash-pinned backend in the venv; the venv's own pip as is (upgrading it is one
# more unpinned download). From a shim, the standby it built is completed
# instead: an older shim leaves out requirements files it does not know.
if [[ "${FROM_UPGRADE_SHIM}" -eq 0 ]]; then
    BOXMUNGE_ROOT="${BOXMUNGE_ROOT}" bash "${SCRIPT_DIR}/bootstrap/venv-deps.sh" active
    "${BOXMUNGE_ROOT}/env-active/bin/pip" install --quiet --no-cache-dir --no-deps --no-build-isolation "${SCRIPT_DIR}"
else
    BOXMUNGE_ROOT="${BOXMUNGE_ROOT}" bash "${SCRIPT_DIR}/bootstrap/venv-deps.sh" standby
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

# deploy's login shell and SFTP wrapper, sshd's SFTP Subsystem, and boxmunge's
# sshd drop-in (key-only logins, no forwarding for deploy).
# shellcheck source=bootstrap/install-ssh.sh
source "${SCRIPT_DIR}/bootstrap/install-ssh.sh"

# ---------------------------------------------------------------------------
# Install the boxmunge-upgrade shim (orchestrates auto-updates)
#
# The bundle's shim is built self-contained (scripts/build-shim.py). A
# pre-release build of this change installed its libraries separately into
# bin/boxmunge-upgrade.d/; nothing reads that any more. Renamed into place, never
# copied over the running shim (bootstrap/install-shim.sh).
# ---------------------------------------------------------------------------
BOXMUNGE_ROOT="${BOXMUNGE_ROOT}" bash "${SCRIPT_DIR}/bootstrap/install-shim.sh"
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
# Sudoers: deploy may run exactly `boxmunge-upgrade auto`, `target <version>`
# and `repair-deps` as root, so the deploy shell's `upgrade`, `--target` and
# `--repair-deps` reach the shim. The rule text lives in the shim
# (install-sudoers), which validates it with visudo before replacing
# /etc/sudoers.d/boxmunge-deploy. Every upgrade rewrites it too, so a box
# carrying an older, wider rule is tightened on upgrade.
# ---------------------------------------------------------------------------
"${BOXMUNGE_ROOT}/bin/boxmunge-upgrade" install-sudoers

# ---------------------------------------------------------------------------
# Record installed version (read by boxmunge auto-update to decide if a
# new release is available). Package is named boxmunge-server in pyproject.
# Run by the upgrade shim, this is before its swap: env-active is still the
# previous release, so the version being installed is the bundle's, and the
# shim's apply records it.
# ---------------------------------------------------------------------------
INSTALLED_VERSION="$(if [[ "${FROM_UPGRADE_SHIM}" -eq 1 ]]; then
        sed -n 's/^version = "\(.*\)"$/\1/p' "${SCRIPT_DIR}/pyproject.toml" | head -n 1
    else
        "${BOXMUNGE_ROOT}/env-active/bin/pip" show boxmunge-server 2>/dev/null | grep '^Version:' | cut -d' ' -f2
    fi)" || true
INSTALLED_VERSION="${INSTALLED_VERSION:-unknown}"

if [[ "${INSTALLED_VERSION}" != "unknown" && "${FROM_UPGRADE_SHIM}" -eq 0 ]]; then
    echo "${INSTALLED_VERSION}" > "${BOXMUNGE_ROOT}/config/version"
fi

# A step noted incomplete (note_incomplete): everything else is in place, so a
# fresh install or an operator's re-run stops here with what to run. Under the
# upgrade shim it only warned. Either way the installer fingerprint goes first,
# so the next upgrade re-runs install.sh to retry it.
fail_if_incomplete() {
    [[ -n "${INCOMPLETE}" ]] || return 0
    BOXMUNGE_ROOT="${BOXMUNGE_ROOT}" bash "${SCRIPT_DIR}/bootstrap/installer-fingerprint.sh" forget
    echo "  Installer fingerprint not recorded: the next upgrade re-runs install.sh" \
         "to retry what did not complete"
    [[ "${FROM_UPGRADE_SHIM}" -eq 0 ]] || return 0
    echo "" >&2
    echo "ERROR: boxmunge is installed, but these steps did not complete (see the WARNINGs above):" >&2
    printf '%s' "${INCOMPLETE}" >&2
    echo "Fix each as it says, then check with: boxmunge doctor" >&2
    exit 1
}
fail_if_incomplete

# Record the installer fingerprint last, so a partial install (which exits
# earlier under `set -e`) leaves the prior one in place and the shim re-runs
# install.sh on the next upgrade (see bootstrap/installer-fingerprint.sh).
if [[ -z "${INCOMPLETE}" ]]; then
    BOXMUNGE_ROOT="${BOXMUNGE_ROOT}" bash "${SCRIPT_DIR}/bootstrap/installer-fingerprint.sh" record "${SCRIPT_DIR}"
fi

echo ""
echo "========================================================"
if [[ -n "${INCOMPLETE}" ]]; then
    echo "  boxmunge ${INSTALLED_VERSION} installed, but not every step completed:"
    printf '%s' "${INCOMPLETE}"
else
    echo "  boxmunge ${INSTALLED_VERSION} installed successfully"
fi
echo "========================================================"
