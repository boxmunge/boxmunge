#!/bin/sh
# Smoke test, run by boxmunge inside the service's container after every
# deploy and by the health monitor:  sh /boxmunge-scripts/smoke.sh <service>
#
# POSIX sh only: the container's /bin/sh may be dash or busybox, not bash.
# Exit 0 when healthy and 1 when degraded, with one line on stderr saying why.
# Never exit 2 unless the project must be stopped: 2 means CRITICAL, and
# boxmunge then stops every container in the project.
set -u

service=${1:-web}
url="http://127.0.0.1:8080/healthz"

if command -v wget >/dev/null 2>&1; then
    wget -q -O /dev/null -T 5 "$url" 2>/dev/null && exit 0
elif command -v curl >/dev/null 2>&1; then
    curl -fsS -o /dev/null --max-time 5 "$url" 2>/dev/null && exit 0
elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=5)' \
        "$url" 2>/dev/null && exit 0
else
    echo "smoke: no wget, curl or python3 in the $service container to probe $url" >&2
    exit 1
fi

echo "smoke: $service did not answer at $url" >&2
exit 1
