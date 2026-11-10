#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/system-container.sh — install this bundle's boxmunge-system
# definition (system/) under BOXMUNGE_ROOT and start the container, rebuilding
# its image unless the running one was built from this definition. Run by
# install.sh, which decides whether a failure stops the install. Exits 3 when
# the image is current but the container did not start, and 1 when the build
# (or the start after it) failed; a container that was already running keeps
# running on its previous image.
#
# The definition is the sha256 of the installed Dockerfile then compose.yml.
# It goes to .env as BOXMUNGE_SYSTEM_DEFINITION, which compose.yml puts on the
# image as the boxmunge.system-definition label, so a rebuild by hand
# (docker compose ... up -d --build) records it too. `health` and `doctor`
# compare that label with the installed files (system_container.stale_image).
# The build tags boxmunge.invalid/system/system, the data helper's image.
set -euo pipefail

BOXMUNGE_ROOT="${BOXMUNGE_ROOT:-/opt/boxmunge}"
BUNDLE="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${BOXMUNGE_ROOT}/system"
COMPOSE="${DEST}/compose.yml"
LABEL="boxmunge.system-definition"
ATTEMPTS=3

mkdir -p "${DEST}"
cp "${BUNDLE}/system/Dockerfile" "${BUNDLE}/system/compose.yml" "${DEST}/"
definition="$(cat "${DEST}/Dockerfile" "${DEST}/compose.yml" | sha256sum | awk '{print $1}')"
# The container runs as the deploy user so it can read the 0600 backup temp
# files and the root:deploy backup key (compose.yml `user:`).
printf 'BOXMUNGE_UID=%s\nBOXMUNGE_GID=%s\nBOXMUNGE_CONFIG=%s\nBOXMUNGE_PROJECTS=%s\nBOXMUNGE_SYSTEM_DEFINITION=%s\n' \
    "$(id -u deploy)" "$(id -g deploy)" \
    "${BOXMUNGE_ROOT}/config" "${BOXMUNGE_ROOT}/projects" "${definition}" > "${DEST}/.env.next"
mv "${DEST}/.env.next" "${DEST}/.env"
chown -R root:root "${DEST}"

# Empty when there is no container yet; the build below then makes one.
running="$(docker inspect --type container --format "{{index .Config.Labels \"${LABEL}\"}}" \
    boxmunge-system 2>/dev/null || true)"
if [[ "${running}" == "${definition}" ]]; then
    # Same image; Compose recreates the container only if .env changed it.
    docker compose -f "${COMPOSE}" up -d && exit 0
    echo "  boxmunge-system did not start (its image is current)" >&2
    exit 3
fi

# A build downloads from GitHub, rclone.org, Docker Hub and Alpine's mirrors:
# retry a transient failure before giving up.
for attempt in $(seq 1 "${ATTEMPTS}"); do
    docker compose -f "${COMPOSE}" up -d --build && exit 0
    if [[ "${attempt}" -lt "${ATTEMPTS}" ]]; then
        echo "  boxmunge-system build failed (attempt ${attempt} of ${ATTEMPTS});" \
             "retrying in $((attempt * 30))s" >&2
        sleep $((attempt * 30))
    fi
done
echo "  boxmunge-system build failed ${ATTEMPTS} times" >&2
exit 1
