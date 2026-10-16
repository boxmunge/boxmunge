# shellcheck shell=bash
# system.sh — release signature check, deploy's sudo rule, on-box docs, and
# the shim's own self-update.
# Part of boxmunge-upgrade (runs as root); scripts/build-shim.py inlines it into
# the shim that releases ship.

# Cosign verification pins. The release workflow keyless-signs SHA256SUMS via
# Sigstore's Fulcio + Rekor. We pin the OIDC issuer and the workflow identity
# so a signature from any other workflow (or any other repo) is rejected.
COSIGN_CERT_IDENTITY_REGEXP='^https://github\.com/boxmunge/boxmunge/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$'
COSIGN_OIDC_ISSUER='https://token.actions.githubusercontent.com'

# verify_release_signature <download_dir>
#
# Verifies $download_dir/SHA256SUMS against $download_dir/SHA256SUMS.sig with
# certificate $download_dir/SHA256SUMS.cert, pinning the certificate identity
# to this repo's release workflow on a vX.Y.Z tag.
#
# Hard-requires cosign on PATH; aborts noisily if missing. Returns 0 on success
# and non-zero on any failure (cosign missing, signature/cert files missing,
# verification failed).
verify_release_signature() {
    local download_dir="${1:?usage: verify_release_signature <download_dir>}"
    if ! command -v cosign >/dev/null 2>&1; then
        log "ERROR: cosign required for upgrade verification but not installed."
        log "       Re-run install.sh on this host, or install cosign manually."
        return 1
    fi
    local sums="$download_dir/SHA256SUMS"
    local sig="$download_dir/SHA256SUMS.sig"
    local cert="$download_dir/SHA256SUMS.cert"
    if [[ ! -f "$sig" || ! -f "$cert" ]]; then
        log "ERROR: cosign signature/certificate not found in release artifacts"
        log "       missing: $([[ -f "$sig" ]] || echo "SHA256SUMS.sig") $([[ -f "$cert" ]] || echo "SHA256SUMS.cert")"
        return 1
    fi
    cosign verify-blob \
        --certificate-identity-regexp "$COSIGN_CERT_IDENTITY_REGEXP" \
        --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" \
        --signature "$sig" \
        --certificate "$cert" \
        "$sums" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# deploy's sudo rule. Owned here so install.sh and every upgrade write the
# same text; a box whose rule predates a tightening is fixed on its next
# upgrade. `target *` cannot reach force-target or any other subcommand:
# sudo matches the whole argument string against the pattern.
# ---------------------------------------------------------------------------
sudoers_rule() {
    cat <<EOF
# Managed by boxmunge-upgrade install-sudoers; rewritten on every install and upgrade.
deploy ALL=(root) NOPASSWD: $BIN_DIR/boxmunge-upgrade auto, $BIN_DIR/boxmunge-upgrade target *
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
# *.md files.
install_docs() {
    local src="$1" docs="$BOXMUNGE_ROOT/docs" stage link previous old=""
    if ! compgen -G "$src/*.md" >/dev/null; then
        log "ERROR: no *.md docs in $src; $docs left unchanged"
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
    if [[ -d "$docs" && ! -L "$docs" ]]; then
        # One-time move from a plain directory (installs before this change).
        old="$stage.old"
        mv "$docs" "$old"
    fi
    replace_file "$link" "$docs"
    [[ -z "$old" ]] || rm -rf "$old"
    if [[ "$previous" =~ ^\.docs\.[A-Za-z0-9]+$ ]]; then rm -rf "${BOXMUNGE_ROOT:?}/$previous"; fi
    log "Installed docs from $src"
}

cmd_install_docs() {
    install_docs "${1:?Usage: boxmunge-upgrade install-docs <dir>}" || die "install-docs failed"
}

# seed_slot_docs <slot>: a slot installed by install.sh (or an older shim)
# has no docs copy; record the live docs as its own so a rollback to it
# restores them.
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
        log "ERROR: docs not refreshed for slot $1 ($src missing or empty); agent-help may be stale"
        bm_log error upgrade "docs refresh failed" "{\"slot\": \"$1\"}"
    fi
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
            install -m 0755 -o root -g root "$new_shim" "$BIN_DIR/boxmunge-upgrade"
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
            install -m 0755 -o root -g root "$f" "$BIN_DIR/$name"
            bm_log info upgrade "wrapper self-updated" "{\"name\": \"$name\"}"
        else
            log "ERROR: new $name has syntax errors; refusing to install. Old wrapper retained."
            bm_log error upgrade "wrapper self-update skipped: bash -n failed" "{\"name\": \"$name\"}"
        fi
    done
}
