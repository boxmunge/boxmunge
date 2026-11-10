# shellcheck shell=bash
# release.sh — release bundles: fetching one and verifying its signature and
# checksum, the hash-pinned requirements a slot is built from, and
# repair-deps, which installs them into the live slot.
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

# require_free_space: an upgrade or a repair needs 250MB under BOXMUNGE_ROOT.
# A slot is about 90MB on Debian, MCP included. pip runs with --no-cache-dir,
# so no wheel cache builds up under /root; the rest is headroom for the stash.
require_free_space() {
    local avail_mb
    avail_mb=$(df -m "$BOXMUNGE_ROOT" | awk 'NR==2{print $4}')
    [[ "$avail_mb" -ge 250 ]] || die "Insufficient disk space: ${avail_mb}MB available, need 250MB"
}

TMP_DOWNLOAD=""
cleanup_download() { [[ -z "$TMP_DOWNLOAD" ]] || rm -rf "$TMP_DOWNLOAD"; }

# start_download: TMP_DOWNLOAD becomes a fresh root-only directory, removed
# when the shim exits.
start_download() {
    TMP_DOWNLOAD="$(mktemp -d)"
    trap cleanup_download EXIT
}

# fetch_release <version> <dir>: download release <version>'s bundle and its
# signed SHA256SUMS into <dir>, verify both, and extract the bundle to
# <dir>/boxmunge. On failure it returns 1 with FETCH_STEP (the step that
# failed, for a blocklist reason) and FETCH_ERROR set; nothing outside <dir>
# has changed. Every step but the last fails on the release or its download;
# bundle_extract fails on the box (the bundle passed its checksum, so it is
# the release's own bytes: a full disk). Callers run it as
# `fetch_release ... || <handle the failure>`, which suspends set -e here, so
# every step checks its own result.
FETCH_STEP=""
FETCH_ERROR=""
# download <dest> <url>: every download runs with upgrade.lock held, so a
# stalled connection must not park the upgrade (and check-probation, which
# skips while the lock is held) indefinitely.
download() { curl -sLf -o "$1" --connect-timeout 30 --max-time 600 --proto =https --proto-redir =https "$2"; }
# shellcheck disable=SC2034  # FETCH_STEP is read by upgrade_to, in the shim itself
fetch_failed() { FETCH_STEP="$1"; FETCH_ERROR="$2"; }

fetch_release() {
    local version="$1" dir="$2"
    local base="https://github.com/boxmunge/boxmunge/releases/download/v${version}"
    local bundle="boxmunge-${version}.tar.gz"

    log "Downloading bundle from ${base}/${bundle}"
    download "$dir/$bundle" "$base/$bundle" \
        || { fetch_failed bundle_download "Failed to download bundle"; return 1; }
    download "$dir/SHA256SUMS" "$base/SHA256SUMS" \
        || { fetch_failed checksum_download "Failed to download SHA256SUMS"; return 1; }
    download "$dir/SHA256SUMS.sig" "$base/SHA256SUMS.sig" \
        || { fetch_failed signature_download "Failed to download SHA256SUMS.sig (release is unsigned or sig artifact missing)"; return 1; }
    download "$dir/SHA256SUMS.cert" "$base/SHA256SUMS.cert" \
        || { fetch_failed certificate_download "Failed to download SHA256SUMS.cert (release is unsigned or cert artifact missing)"; return 1; }

    # Verify cosign signature on SHA256SUMS BEFORE running sha256sum -c.
    #
    # This breaks the circularity of the prior design (where SHA256SUMS and
    # the bundle came from the same release URL — an attacker who replaced
    # the bundle could replace SHA256SUMS in lockstep). Cosign's keyless
    # signature chains to a Fulcio cert tying SHA256SUMS to the release
    # workflow on a tagged release of this exact repo; without the OIDC
    # issuer pinning the attacker would need to compromise GitHub Actions
    # OIDC, not just the release artifacts.
    #
    # cosign is hard-required: if the host is missing it, abort.
    verify_release_signature "$dir" \
        || { fetch_failed cosign_verify "Cosign verification of SHA256SUMS FAILED — refusing to install."; return 1; }
    log "Cosign signature on SHA256SUMS verified (release-workflow identity)"
    bm_log info upgrade "signature verified" "{\"version\": \"$version\"}"

    # Verify checksum.
    #
    # SHA256SUMS lines are produced by `sha256sum <file>` and have the
    # canonical form: `<64-hex-hash>  <filename>` (two spaces, bare filename
    # — the release workflow takes care to write bare filenames).
    #
    # We do NOT pass --ignore-missing: it makes `sha256sum -c` succeed when
    # the SHA256SUMS file lists zero matching files. An adversary who could
    # publish a SHA256SUMS without a line for our bundle would then pass
    # verification trivially. So instead we (a) require that SHA256SUMS
    # contains a line for the exact bundle filename we just downloaded, and
    # (b) run the full check. SHA256SUMS may also list boxmunge-install.sh and
    # other release artefacts we did not download; the check is restricted to
    # the bundle line.
    grep -q "  ${bundle}\$" "$dir/SHA256SUMS" \
        || { fetch_failed checksum_missing_entry "Checksum verification FAILED: SHA256SUMS does not list ${bundle}"; return 1; }
    (cd "$dir" && grep "  ${bundle}\$" SHA256SUMS | sha256sum -c -) \
        || { fetch_failed checksum_mismatch "Checksum verification FAILED"; return 1; }

    local out
    out="$(tar xzf "$dir/$bundle" -C "$dir" 2>&1)" \
        || { fetch_failed bundle_extract "Failed to extract the verified bundle in $dir: $out"; return 1; }
}

# The bundle's hash-pinned requirements files (covered by the signed
# SHA256SUMS). A slot gets every one, in one pip run: it is built from
# scratch, so anything left out is gone after the swap, and without
# requirements-mcp.txt agents cannot operate the box.
PINNED_REQUIREMENTS=(requirements-build.txt requirements-tui.txt requirements-mcp.txt)

# missing_requirement <bundle>: print the first PINNED_REQUIREMENTS file
# <bundle> lacks; returns 1 when it has them all.
missing_requirement() {
    local req
    for req in "${PINNED_REQUIREMENTS[@]}"; do
        [[ -f "$1/$req" ]] || { echo "$req"; return 0; }
    done
    return 1
}

# install_pinned_deps <bundle> <slot>: install every PINNED_REQUIREMENTS file
# of <bundle> into env-<slot>, hash-checked, so nothing beyond the pins is
# resolved. No pip self-upgrade (one more unpinned download) and no cache
# (nothing builds up under /root). Check missing_requirement first.
install_pinned_deps() {
    local req reqs=()
    for req in "${PINNED_REQUIREMENTS[@]}"; do reqs+=(-r "$1/$req"); done
    "$BOXMUNGE_ROOT/env-$2/bin/pip" install --quiet --no-cache-dir --require-hashes "${reqs[@]}"
}

# repair-deps: install the installed release's hash-pinned dependencies into
# the live slot, from that release's own bundle, fetched and verified as an
# upgrade fetches it. An upgrade is run by the box's current shim, which
# installs only the requirements files it knows: up to 0.10.1 that left
# requirements-mcp.txt out, so the new release came up without MCP. pip
# leaves what is already installed as pinned alone; no slot is built,
# swapped or removed. Deploy may sudo it (with no arguments). Allowed during
# probation: it changes only the live slot, never the standby a rollback
# needs.
cmd_repair_deps() {
    [[ $# -eq 0 ]] || die "Usage: boxmunge-upgrade repair-deps"
    load_active_slot
    acquire_lock
    if work_interrupted; then
        die "Not repairing: an earlier upgrade or rollback was interrupted, and the health timer's check-probation finishes it within minutes. Retry after that."
    fi
    local version running missing
    version="$(installed_version)"
    running="$(slot_version "$ACTIVE_SLOT")"
    [[ "$running" == "$version" ]] \
        || die "The live slot env-$ACTIVE_SLOT runs boxmunge '${running:-nothing}', but $VERSION_FILE records $version; refusing to install $version's dependencies into it. Inspect it as supervisor"

    require_free_space
    log "Repairing the hash-pinned dependencies of $version in the live slot $ACTIVE_SLOT"
    start_download
    fetch_release "$version" "$TMP_DOWNLOAD" || die "$FETCH_ERROR (nothing was changed)"
    if missing="$(missing_requirement "$TMP_DOWNLOAD/boxmunge")"; then
        die "Bundle $version has no hash-pinned $missing; refusing an unpinned install. Nothing was changed."
    fi
    # A live slot this breaks: during probation the health timer rolls it back.
    local broken="inspect env-$ACTIVE_SLOT as supervisor"
    [[ ! -e "$PROBATION_FILE" ]] \
        || broken="$version is on probation, so the health timer rolls back to the previous release once two of its runs in a row (5 minutes apart) find it so"
    if ! install_pinned_deps "$TMP_DOWNLOAD/boxmunge" "$ACTIVE_SLOT"; then
        local state="its boxmunge-server still runs"
        slot_works "$ACTIVE_SLOT" || state="its boxmunge-server NO LONGER RUNS ($broken)"
        die "pip could not install the hash-pinned dependencies of $version into the live slot $ACTIVE_SLOT (see above), and $state; retry once the cause (network, disk space) is fixed"
    fi
    slot_works "$ACTIVE_SLOT" \
        || die "env-$ACTIVE_SLOT/bin/boxmunge-server no longer runs after the dependency install; $broken"
    bm_log info upgrade "dependencies repaired" "{\"version\": \"$version\", \"slot\": \"$ACTIVE_SLOT\"}"
    log "Installed every hash-pinned dependency of $version into the live slot $ACTIVE_SLOT"
}
