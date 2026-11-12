#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/unresolved-stage.sh: refuse to install this release by hand over a
# box where a project still holds a release that boxmunge 0.10.1 or earlier
# staged over production's files. Run by install.sh on an existing box, before
# it changes anything.
#
# Releases 0.11.0 to 0.11.6 resolve such a stage with their `legacy-stage`
# command. This release has none, so once it is installed nothing on the box
# resolves the stage. An upgrade is refused in the shim's pre-flight (the
# upgrade's dry run, refuse_unresolved_stages), so the shim's run of
# install.sh is not checked again. This check goes, with
# src/boxmunge/unresolved_stage.py and unresolved_stage_install.py, when the
# upgrade floor reaches 0.11.7: a box on 0.11.7 or later holds no such stage.
#
# The detector is the upgrade's own (boxmunge.unresolved_stage), run from this
# bundle's src/ before the package is installed. It needs only the standard
# library, so the host's python3 runs it: without site-packages (-S), apart
# from the caller's environment and directory (-I), and writing no bytecode
# into the bundle (-B). Not the box's venv: an interrupted first install has
# config/boxmunge.yml and no venv, and re-running the installer finishes it.
# install.sh has already checked that python3 is new enough
# (bootstrap/python-floor.sh). No alert is sent: whoever runs install.sh reads
# the terminal. A check that cannot run is an error, not a pass.
set -euo pipefail

BOXMUNGE_ROOT="${BOXMUNGE_ROOT:-/opt/boxmunge}"
[[ "${FROM_UPGRADE_SHIM:?install.sh sets it: 1 under the upgrade shim, else 0}" -eq 0 ]] || exit 0
SRC="$(cd "$(dirname "$0")/.." && pwd)/src"

status=0
refusal="$(python3 -I -S -B -c 'import sys
sys.path.insert(0, sys.argv[1])
from boxmunge.unresolved_stage_install import main
sys.exit(main(sys.argv[2]))' "${SRC}" "${BOXMUNGE_ROOT}")" || status=$?
case "${status}" in
    0) exit 0 ;;
    10) echo "ERROR: this install is refused. Nothing was changed." >&2
        echo "${refusal}" >&2 ;;
    *) echo "ERROR: could not check this box for a release that boxmunge 0.10.1 or earlier" >&2
       echo "       staged over production's files (python3 exit ${status})." >&2
       echo "       Nothing was changed. Fix what is reported above, then" >&2
       echo "       run the install again." >&2 ;;
esac
exit 1
