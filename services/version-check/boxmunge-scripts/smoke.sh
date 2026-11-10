#!/usr/bin/env sh
# Verify the service is up, then warn while upgrade failures for a release
# pile up. /healthz is not counted in the check statistics; /v1/check is, so
# a smoke test that called it would drown the real numbers.
# Uses python (always available in this image) — alpine slim doesn't ship curl.
# The smoke test runs inside the service's container (docker exec), so it
# reaches the service as web:8147 and reads the database at /data.
#
# Failure reports never hold a release (they are unauthenticated). When a
# release's reports come from enough networks, failure_alert.py prints one
# line naming it and how to hold it, and exits 1: boxmunge's health check
# reports that as a warning and alerts the operator once per message. It
# runs on the periodic health check only (BOXMUNGE_CHECK=periodic): every
# other smoke run gates an operation (deploy, recover, a quarantine lift,
# bring-up), and reports anyone can send must not hold one up. Never exit 2
# here: that is critical, and boxmunge would stop the service.
set -eu

python3 -c "
import sys, json, urllib.request
try:
    with urllib.request.urlopen('http://web:8147/healthz', timeout=5) as r:
        data = json.loads(r.read())
except Exception as e:
    print(f'FAIL: /healthz endpoint unreachable: {e}', file=sys.stderr)
    sys.exit(1)
if data.get('status') != 'ok':
    print(f'FAIL: /healthz did not report ok: {data}', file=sys.stderr)
    sys.exit(1)
" || exit 1

if [ "${BOXMUNGE_CHECK:-}" = periodic ]; then
    python3 /app/failure_alert.py /data/checks.db || exit 1
fi
echo 'OK: version-check service healthy'
