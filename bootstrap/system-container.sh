#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/system-container.sh — install this bundle's boxmunge-system
# definition (system/) under BOXMUNGE_ROOT and (re)build and start the
# container when the definition changed since its last successful build, or
# the container is not there. Run by install.sh, which decides whether a
# failure stops the install. Exits non-zero if the build or start failed; a
# container that was already running keeps running on its previous image.
#
# The build tags boxmunge.invalid/system/system, the data helper's image.
set -euo pipefail

BOXMUNGE_ROOT="${BOXMUNGE_ROOT:-/opt/boxmunge}"
BUNDLE="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${BOXMUNGE_ROOT}/system"
# sha256 of the Dockerfile, compose.yml and .env the running image was built
# from, written only after a successful build. The files themselves are
# installed before the build, so after a failed one only this says to retry.
BUILT_FROM="${DEST}/.built-from"

mkdir -p "${DEST}"
cp "${BUNDLE}/system/Dockerfile" "${BUNDLE}/system/compose.yml" "${DEST}/"
# The container runs as the deploy user so it can read the 0600 backup temp
# files and the root:deploy backup key (compose.yml `user:`).
printf 'BOXMUNGE_UID=%s\nBOXMUNGE_GID=%s\nBOXMUNGE_CONFIG=%s\nBOXMUNGE_PROJECTS=%s\n' \
    "$(id -u deploy)" "$(id -g deploy)" \
    "${BOXMUNGE_ROOT}/config" "${BOXMUNGE_ROOT}/projects" > "${DEST}/.env.next"
mv "${DEST}/.env.next" "${DEST}/.env"
chown -R root:root "${DEST}"

definition="$(cat "${DEST}/Dockerfile" "${DEST}/compose.yml" "${DEST}/.env" | sha256sum | awk '{print $1}')"
if [[ -f "${BUILT_FROM}" && "$(cat "${BUILT_FROM}")" == "${definition}" ]] \
        && docker inspect boxmunge-system >/dev/null 2>&1; then
    exit 0
fi
docker compose -f "${DEST}/compose.yml" up -d --build
echo "${definition}" > "${BUILT_FROM}"
