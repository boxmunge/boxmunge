# shellcheck shell=bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/cosign.sh — the cosign the upgrade shim verifies every release's
# signature with (hard-required, no fallback). Sourced by install.sh, and by
# the CI arm64 job, which installs and runs the real binary.
#
# The binary is pinned by version and per-architecture SHA256, so a
# compromised GitHub release page cannot swap in a malicious cosign. The
# hashes come from upstream's cosign_checksums.txt for the same release
# (keyless-signed by Sigstore; check it with cosign verify-blob).

COSIGN_VERSION="v2.4.1"
COSIGN_BIN="/usr/local/bin/cosign"

# cosign_sha256 <debian-arch>: the pinned SHA256 of cosign-linux-<arch>.
# Fails for an architecture with no pin; install.sh refuses such hosts up
# front, and system/Dockerfile pins age and rclone for the same two.
cosign_sha256() {
    case "$1" in
        amd64) echo "8b24b946dd5809c6bd93de08033bcf6bc0ed7d336b7785787c080f574b89249b" ;;
        arm64) echo "3b2e2e3854d0356c45fe6607047526ccd04742d20bd44afb5be91fa2a6e7cb4a" ;;
        *) return 1 ;;
    esac
}

# install_cosign <debian-arch>: install the pinned cosign at COSIGN_BIN unless
# the file there already has the pinned hash. Anything else there (another
# version, or the amd64 build installers before 0.11.4 put on arm64 hosts) is
# replaced; nothing unverified is run. Sets an EXIT trap while it downloads
# (install.sh has none of its own).
install_cosign() {
    local arch="$1" sha256
    if ! sha256="$(cosign_sha256 "${arch}")"; then
        echo "ERROR: no cosign pin for architecture ${arch}" >&2
        return 1
    fi
    if [[ -f "${COSIGN_BIN}" ]] && echo "${sha256}  ${COSIGN_BIN}" | sha256sum -c --status -; then
        return 0
    fi
    [[ ! -e "${COSIGN_BIN}" ]] || echo "  ${COSIGN_BIN} is not the pinned cosign ${COSIGN_VERSION} for ${arch}; replacing it"
    echo "  Installing cosign ${COSIGN_VERSION} (${arch})..."
    COSIGN_DOWNLOAD="$(mktemp)"
    trap 'rm -f "${COSIGN_DOWNLOAD}"' EXIT
    curl -sSLf "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-${arch}" -o "${COSIGN_DOWNLOAD}"
    echo "${sha256}  ${COSIGN_DOWNLOAD}" | sha256sum -c -
    install -m 0755 "${COSIGN_DOWNLOAD}" "${COSIGN_BIN}"
    rm -f "${COSIGN_DOWNLOAD}"
    trap - EXIT
    if ! "${COSIGN_BIN}" version >/dev/null 2>&1; then
        echo "ERROR: the installed ${COSIGN_BIN} does not run on this ${arch} host" >&2
        return 1
    fi
}
