#!/bin/sh
# Run by boxmunge inside the backend container after every deploy and by the
# health monitor. Exit 0 when healthy, 1 when degraded.
set -u

if wget -q -O /dev/null -T 5 http://127.0.0.1:9090/api/health 2>/dev/null; then
    exit 0
fi
echo "smoke: backend did not answer at /api/health" >&2
exit 1
