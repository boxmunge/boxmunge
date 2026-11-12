# shellcheck shell=bash
# system.sh — deploy's sudo rule, on-box docs, the shim's own self-update and
# the system upgrade (the bundle's install.sh re-run).
# Part of boxmunge-upgrade (runs as root); scripts/build-shim.py inlines it into
# the shim that releases ship.

# ---------------------------------------------------------------------------
# deploy's sudo rule. Owned here so install.sh and every upgrade write the
# same text; a box whose rule predates a tightening is fixed on its next
# upgrade. sudo matches the whole argument string against each pattern, so
# `target *`, `check *` and `guide *` cannot reach force-target, _check-run
# or any other subcommand (each verb takes exactly one version), and `auto`
# and `repair-deps` take no further words.
# ---------------------------------------------------------------------------
sudoers_rule() {
    cat <<EOF
# Managed by boxmunge-upgrade install-sudoers; rewritten on every install and upgrade.
deploy ALL=(root) NOPASSWD: $BIN_DIR/boxmunge-upgrade auto, $BIN_DIR/boxmunge-upgrade target *, $BIN_DIR/boxmunge-upgrade repair-deps, $BIN_DIR/boxmunge-upgrade check *, $BIN_DIR/boxmunge-upgrade guide *
EOF
}

cmd_install_sudoers() {
    local tmp
    if [[ -f "$SUDOERS_FILE" && ! -L "$SUDOERS_FILE" ]] && cmp -s <(sudoers_rule) "$SUDOERS_FILE"; then
        return 0
    fi
    # A dot in the name keeps sudo from reading the temp file mid-write.
    tmp="$(mktemp "$(dirname "$SUDOERS_FILE")/.boxmunge-deploy.XXXXXX")"
    sudoers_rule > "$tmp"
    chmod 0440 "$tmp"
    if ! visudo -cqf "$tmp" >/dev/null; then
        rm -f "$tmp"
        die "Generated sudoers rule failed visudo; $SUDOERS_FILE left unchanged"
    fi
    replace_file "$tmp" "$SUDOERS_FILE"
    log "Wrote deploy sudo rule to $SUDOERS_FILE"
}

# ---------------------------------------------------------------------------
# On-box docs (served by agent-help). Each venv slot keeps the docs of the
# release it holds in env-<slot>/boxmunge-docs, so a rollback can put the
# matching docs back. docs/ is a symlink to a versioned sibling directory and
# is swapped by rename: a reader sees the old set or the new set, never a
# partial or empty one. Doc files missing from the new set disappear.
# ---------------------------------------------------------------------------
slot_docs() { echo "$BOXMUNGE_ROOT/env-$1/boxmunge-docs"; }

# install_docs <dir>: returns non-zero (and changes nothing) if <dir> has no
# *.md files, or if docs/ is anything but the link (a rename cannot replace a
# directory with a link, and what is in one is not boxmunge's to delete).
install_docs() {
    local src="$1" docs="$BOXMUNGE_ROOT/docs" stage link previous
    if ! compgen -G "$src/*.md" >/dev/null; then
        log "ERROR: no *.md docs in $src; $docs left unchanged"
        return 1
    fi
    if [[ -e "$docs" && ! -L "$docs" ]]; then
        log "ERROR: $docs is not the link boxmunge keeps there, so the docs were not installed and it is left unchanged. Move it aside (sudo mv $docs $docs.old), then run the install or upgrade again"
        return 1
    fi
    stage="$(mktemp -d "$BOXMUNGE_ROOT/.docs.XXXXXX")"
    cp "$src"/*.md "$stage/"
    chmod 0644 "$stage"/*.md
    chmod 0755 "$stage"
    if [[ "$(id -u)" -eq 0 ]]; then chown -R root:root "$stage"; fi
    link="$stage.link"
    ln -s "$(basename "$stage")" "$link"
    previous="$(readlink "$docs" 2>/dev/null || true)"
    if ! replace_file "$link" "$docs"; then
        rm -rf "$stage" "$link"
        log "ERROR: could not replace $docs (see above); it is left unchanged"
        return 1
    fi
    if [[ "$previous" =~ ^\.docs\.[A-Za-z0-9]+$ ]]; then rm -rf "${BOXMUNGE_ROOT:?}/$previous"; fi
    log "Installed docs from $src"
}

cmd_install_docs() {
    local src="${1:?Usage: boxmunge-upgrade install-docs <dir>}"
    [[ "$src" == /* ]] || die "install-docs needs an absolute path (the shim runs from /), not '$src'"
    install_docs "$src" || die "install-docs failed"
}

# seed_slot_docs <slot>: a slot installed by install.sh has no docs copy;
# record the live docs as its own so a rollback to it restores them.
seed_slot_docs() {
    local dest
    dest="$(slot_docs "$1")"
    if [[ ! -d "$dest" ]] && compgen -G "$BOXMUNGE_ROOT/docs/*.md" >/dev/null; then
        mkdir -p "$dest"
        cp "$BOXMUNGE_ROOT/docs/"*.md "$dest/"
    fi
}

# refresh_docs_for_slot <slot>: best effort, because a docs failure must not
# undo an upgrade or a rollback. Logged loudly so it is not missed.
refresh_docs_for_slot() {
    local src
    src="$(slot_docs "$1")"
    if [[ ! -d "$src" ]] || ! install_docs "$src"; then
        log "ERROR: docs not refreshed for slot $1 from $src (missing, empty, or refused above); agent-help may be stale"
        bm_log error upgrade "docs refresh failed" "{\"slot\": \"$1\"}"
    fi
}

# install_by_rename <src> <dest>: <src> as <dest>, 0755 and root's (root
# makes the temp), through a temp file renamed over <dest>. install(1)
# truncates and rewrites <dest> in place, and bash reads a script from its
# file as it runs: writing through the running shim's inode would hand this
# very upgrade the new bytes part-way through (sshd execs boxmunge-sftp for
# every SFTP request, too). A temp a run killed before its rename is removed
# by the next (bin/ is root's, and every caller holds upgrade.lock).
install_by_rename() {
    local tmp prefix
    prefix="$(dirname "$2")/.$(basename "$2")"
    rm -f "$prefix".*
    tmp="$(mktemp "$prefix.XXXXXX")"
    { cp "$1" "$tmp" && chmod 0755 "$tmp" && mv -f "$tmp" "$2"; } || { rm -f "$tmp"; return 1; }
}

# self_update_shim <bundle_dir>: install the bundle's shim (and other bin/
# wrappers) over the running ones. Without this, shim fixes would take effect
# only on the upgrade after they ship. Gated on `bash -n`, and on the shim
# being a built one: a syntactically broken or unbuilt shim would brick
# `boxmunge-upgrade` until install.sh is re-run, so it is refused and the
# running shim kept (the venv install still goes ahead; the fix is just
# deferred to the next release).
self_update_shim() {
    local bundle="$1" new_shim="$1/scripts/boxmunge-upgrade" f name
    if [[ -f "$new_shim" ]]; then
        if ! bash -n "$new_shim" 2>/dev/null; then
            log "ERROR: new shim has syntax errors; refusing to install. Old shim retained."
            bm_log error upgrade "shim self-update skipped: bash -n failed" "{}"
        elif grep -q '^# >>> boxmunge-upgrade.d:' "$new_shim"; then
            log "ERROR: bundle carries an unbuilt source shim; refusing to install. Old shim retained."
            bm_log error upgrade "shim self-update skipped: unbuilt shim" "{}"
        else
            log "Self-updating upgrade shim from bundle..."
            install_by_rename "$new_shim" "$BIN_DIR/boxmunge-upgrade"
            bm_log info upgrade "shim self-updated" "{}"
        fi
    fi
    # Other wrappers under bin/ the bundle ships. boxmunge-sftp is the SFTP
    # wrapper invoked by sshd (it refuses deploy).
    # shellcheck disable=SC2043  # one wrapper today; new bin/ wrappers go in this list
    for name in boxmunge-sftp; do
        f="$bundle/scripts/$name"
        [[ -f "$f" ]] || continue
        if bash -n "$f" 2>/dev/null; then
            install_by_rename "$f" "$BIN_DIR/$name"
            bm_log info upgrade "wrapper self-updated" "{\"name\": \"$name\"}"
        else
            log "ERROR: new $name has syntax errors; refusing to install. Old wrapper retained."
            bm_log error upgrade "wrapper self-update skipped: bash -n failed" "{\"name\": \"$name\"}"
        fi
    done
}

# ---------------------------------------------------------------------------
# System upgrade: re-run the bundle's install.sh before the slot swap when it
# differs from the one this box last ran, so new system pieces (apt packages,
# systemd units, Caddy's compose file, install.sh-only migrations) are in
# place by the time the new venv goes live. install.sh records a fingerprint of itself and the files it
# installs from at the end of every successful run; the shim computes the same
# over the new bundle (tests/test_installer_fingerprint.py).
# ---------------------------------------------------------------------------

# installer_fingerprint: print the fingerprint install.sh last recorded, or
# nothing when there is none. It is in root-only upgrade-root/. Releases up to
# 0.11.3 kept it in deploy-writable state/, which is never read: deploy could
# put a link there (root would read the target into the logs), a FIFO (the
# upgrade would block with the lock held) or the bundle's own hash (root
# would skip install.sh). A box upgrading from one of those has none here
# yet, so install.sh runs once, the safe default, and records it.
installer_fingerprint() {
    refuse_symlink "$UPGRADE_ROOT_DIR"
    refuse_symlink "$INSTALLER_HASH_FILE"
    [[ -e "$INSTALLER_HASH_FILE" ]] || return 0
    read_untrusted "$INSTALLER_HASH_FILE"
}

# system_upgrade <bundle_dir> <version> <from_version>: install.sh is gated on
# `bash -n` like the shim's self-update: a syntactically broken one must not
# brick the box. If it fails, the upgrade fails before the swap (the version
# is blocklisted, the previous venv stays live) and the operator diagnoses it.
# Called with --upgrade-shim, install.sh touches no venv: the shim has built
# the standby from the bundle's hash-pinned requirements already.
system_upgrade() {
    local bundle="$1" version="$2" from_version="$3"
    local new_install_sh="$1/install.sh" new_hash current_hash sysup_exit=0
    [[ -f "$new_install_sh" ]] || return 0
    if ! bash -n "$new_install_sh" 2>/dev/null; then
        bm_log error upgrade "system upgrade skipped: bash -n failed" "{\"version\": \"$version\"}"
        preflight_fail "$version" "$from_version" "system_upgrade_failed: install_sh_syntax" \
            "ERROR: bundled install.sh has syntax errors; refusing to run system upgrade" system_upgrade
    fi
    new_hash="$( (cd "$bundle" && find . \( -path ./install.sh -o -path './bootstrap/*' -o -path './src/boxmunge/sshd/*' -o -path './system/*' -o -path './systemd/*' -o -path ./caddy/compose.yml -o -path './caddy/maintenance/*' \) -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum) | sha256sum | awk '{print $1}')"
    current_hash="$(installer_fingerprint)" || exit 1
    if [[ "$new_hash" == "$current_hash" ]]; then
        log "install.sh unchanged (${new_hash:0:8}); skipping system upgrade"
        return 0
    fi
    if [[ -z "$current_hash" ]]; then
        log "No installer fingerprint in $UPGRADE_ROOT_DIR (new=${new_hash:0:8}); running system upgrade..."
    else
        log "install.sh changed (current=$(printable "${current_hash:0:8}"), new=${new_hash:0:8}); running system upgrade..."
    fi
    bm_log info upgrade "system upgrade started" \
        "{\"new_hash\": \"${new_hash:0:16}\", \"prev_hash\": \"$(printable "${current_hash:0:16}")\"}"
    bash "$new_install_sh" --upgrade-shim || sysup_exit=$?
    if [[ "$sysup_exit" -ne 0 ]]; then
        bm_log error upgrade "system upgrade failed" "{\"exit_code\": $sysup_exit}"
        preflight_fail "$version" "$from_version" "system_upgrade_failed: install_sh_exit_${sysup_exit}" \
            "ERROR: install.sh failed (exit ${sysup_exit}); aborting upgrade before slot swap" system_upgrade
    fi
    bm_log info upgrade "system upgrade completed" "{\"hash\": \"${new_hash:0:16}\"}"
}
