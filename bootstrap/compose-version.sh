#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/compose-version.sh — exit 1, naming the fix, unless Docker Compose
# is at least MIN_COMPOSE_VERSION. Run by install.sh: on an upgrade before
# anything is changed, on a fresh install right after the bootstrap has
# installed Docker.
#
# boxmunge resolves user compose with `config --no-env-resolution`, which
# Compose accepts from 2.35.0 (2.34 and older: "unknown flag"). That also
# covers secrets' single-quoted env-file values with \' for a quote, which
# Compose reads literally from 2.24 on. Keep in step with MIN_COMPOSE_VERSION
# in src/boxmunge/compose_version.py, which applies the same rule: trim ASCII
# whitespace, then the whole output must be one version with an optional
# packaging suffix; anything else is reported as unreadable, never guessed at.
set -euo pipefail

MIN_COMPOSE_VERSION="2.35.0"
ws=$' \t\r\n\v\f'
if ! raw="$(docker compose version --short 2>/dev/null)"; then
    echo "ERROR: 'docker compose version --short' failed. Install" \
         "docker-compose-plugin ${MIN_COMPOSE_VERSION} or newer from Docker's apt repository." >&2
    exit 1
fi
found="${raw#"${raw%%[!"${ws}"]*}"}"
found="${found%"${found##*[!"${ws}"]}"}"
re='^v?([0-9]+)\.([0-9]+)\.([0-9]+)([-+][^'"${ws}"']*)?$'
if [[ ! "${found}" =~ ${re} ]]; then
    echo "ERROR: could not read the Docker Compose version from" \
         "'docker compose version --short', which printed: $(printf '%q' "${raw}")" >&2
    exit 1
fi
have=( "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" )
IFS=. read -r -a want <<< "${MIN_COMPOSE_VERSION}"
for i in 0 1 2; do
    (( 10#${have[i]} > 10#${want[i]} )) && exit 0
    if (( 10#${have[i]} < 10#${want[i]} )); then
        echo "ERROR: Docker Compose ${found} is older than ${MIN_COMPOSE_VERSION}," \
             "which boxmunge needs to pass secrets to containers unchanged." \
             "Upgrade it: apt-get install --only-upgrade docker-compose-plugin" >&2
        exit 1
    fi
done
