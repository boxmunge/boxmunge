# shellcheck shell=bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/cosign.sh — the pinned cosign builds: the one the upgrade shim
# verifies every release's signature with (hard-required, no fallback), and
# the one release signing moves to. Sourced by install.sh, by the CI arm64
# job, which installs and runs the real binary, and by the cosign rehearsal
# workflow (.github/workflows/cosign-rehearsal.yml), which signs with
# COSIGN_SIGN_VERSION and verifies with both.
#
# Each binary is pinned by version and per-architecture SHA256, so a
# compromised GitHub release page cannot swap in a malicious cosign. The
# hashes come from upstream's cosign_checksums.txt for the same release
# (keyless-signed by Sigstore; check it with cosign verify-blob).

# The box's cosign: what install.sh installs and the shim verifies with.
COSIGN_VERSION="v2.4.1"
# What releases are to be signed with, and the boxes' next pin. Only the CI
# rehearsal uses it so far.
# shellcheck disable=SC2034  # read by .github/workflows/cosign-rehearsal.yml
COSIGN_SIGN_VERSION="v3.1.4"
COSIGN_BIN="/usr/local/bin/cosign"

# cosign_sha256 <debian-arch> [<version>]: the pinned SHA256 of
# cosign-linux-<arch> of <version> (by default COSIGN_VERSION). Fails for a
# version or architecture with no pin; install.sh refuses such hosts up
# front, and system/Dockerfile pins age and rclone for the same two.
cosign_sha256() {
    case "${2:-${COSIGN_VERSION}} $1" in
        "v2.4.1 amd64") echo "8b24b946dd5809c6bd93de08033bcf6bc0ed7d336b7785787c080f574b89249b" ;;
        "v2.4.1 arm64") echo "3b2e2e3854d0356c45fe6607047526ccd04742d20bd44afb5be91fa2a6e7cb4a" ;;
        "v3.1.4 amd64") echo "424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa" ;;
        "v3.1.4 arm64") echo "ade83b7aac62e131cacfe96d958948b2150cc9efec46a570a2649b8e27dedad2" ;;
        *) return 1 ;;
    esac
}

# install_cosign <debian-arch> [<version>]: install the pinned cosign
# <version> (by default COSIGN_VERSION) at COSIGN_BIN, unless the file there
# already has the pinned hash. Anything else there (another version, or the
# amd64 build installers before 0.11.4 put on arm64 hosts) is replaced;
# nothing unverified is run. Sets an EXIT trap while it downloads (install.sh
# has none of its own).
install_cosign() {
    local arch="$1" version="${2:-${COSIGN_VERSION}}" sha256
    if ! sha256="$(cosign_sha256 "${arch}" "${version}")"; then
        echo "ERROR: no cosign ${version} pin for architecture ${arch}" >&2
        return 1
    fi
    if [[ -f "${COSIGN_BIN}" ]] && echo "${sha256}  ${COSIGN_BIN}" | sha256sum -c --status -; then
        return 0
    fi
    [[ ! -e "${COSIGN_BIN}" ]] || echo "  ${COSIGN_BIN} is not the pinned cosign ${version} for ${arch}; replacing it"
    echo "  Installing cosign ${version} (${arch})..."
    COSIGN_DOWNLOAD="$(mktemp)"
    trap 'rm -f "${COSIGN_DOWNLOAD}"' EXIT
    curl -sSLf --proto =https --proto-redir =https --connect-timeout 30 --max-time 600 "https://github.com/sigstore/cosign/releases/download/${version}/cosign-linux-${arch}" -o "${COSIGN_DOWNLOAD}"
    echo "${sha256}  ${COSIGN_DOWNLOAD}" | sha256sum -c -
    install -m 0755 "${COSIGN_DOWNLOAD}" "${COSIGN_BIN}"
    rm -f "${COSIGN_DOWNLOAD}"
    trap - EXIT
    if ! "${COSIGN_BIN}" version >/dev/null 2>&1; then
        echo "ERROR: the installed ${COSIGN_BIN} does not run on this ${arch} host" >&2
        return 1
    fi
}
