#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/audit-seal.sh: seal the action audit log, logs/audit.jsonl, as
# root: deploy's, 0640, append-only (`boxmunge-server _audit-seal`). Run by
# install.sh once this release's venv is installed, before the units (the
# monthly rotation timer and the API's writers expect a sealed log).
#
# Run by hand, this release is in env-active. Run by the upgrade shim
# (FROM_UPGRADE_SHIM=1), env-active is still the previous release, which has
# no _audit-seal: this release is in the shim's standby slot, the one
# env-active does not name. env-active is root's, in root's directory.
#
# A host that cannot set the attribute (a filesystem without it, a container
# without CAP_LINUX_IMMUTABLE) installs anyway: _audit-seal records why in
# root-only upgrade-root/audit-append-unsupported and prints a WARNING that deploy can rewrite
# the audit log on this host; `health` warns. Any other failure fails install.
set -euo pipefail

BOXMUNGE_ROOT="${BOXMUNGE_ROOT:-/opt/boxmunge}"
venv="${BOXMUNGE_ROOT}/env-active"
if [[ "${FROM_UPGRADE_SHIM:-0}" == 1 ]]; then
    live="$(readlink "${BOXMUNGE_ROOT}/env-active")"
    case "${live##*/}" in
        env-a) venv="${BOXMUNGE_ROOT}/env-b" ;;
        env-b) venv="${BOXMUNGE_ROOT}/env-a" ;;
        *) echo "ERROR: ${BOXMUNGE_ROOT}/env-active points at '${live}', not env-a or env-b," \
                "so the slot holding this release is unknown and the audit log was not sealed." \
                "Point it back at the live slot, then run the upgrade again." >&2
           exit 1 ;;
    esac
fi

echo ""
echo "========================================================"
echo "  Sealing the audit log (append-only)"
echo "========================================================"
"${venv}/bin/boxmunge-server" _audit-seal
