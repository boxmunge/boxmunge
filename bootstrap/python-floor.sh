# shellcheck shell=bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/python-floor.sh: refuse a host whose python3 is older than the
# server package's floor (requires-python in pyproject.toml), which Debian 13
# ships. On an older python3 the venv builds and the hash-pinned install then
# fails halfway with a resolver error. Sourced by install.sh.
MIN_PYTHON="3.13"
require_python_floor() {
    local found have="this host has no python3"
    if ! found="$(python3 -I -c 'import sys
print("%d.%d.%d" % sys.version_info[:3])
sys.exit(sys.version_info[:2] < tuple(map(int, sys.argv[1].split("."))))' "${MIN_PYTHON}" 2>/dev/null)"; then
        [[ -z "${found}" ]] || have="this host's python3 is ${found}"
        echo "ERROR: boxmunge needs Python ${MIN_PYTHON} or newer; ${have}." \
             "Install it on a Debian 13 VPS, which ships Python ${MIN_PYTHON}." >&2
        exit 1
    fi
}
