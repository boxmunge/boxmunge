#!/usr/bin/env bash
set -euo pipefail

# Check backend health
status=$(curl -sf -o /dev/null -w "%{http_code}" http://sample-backend:9090/api/health 2>/dev/null || true)
if [[ "$status" != "200" ]]; then
    echo "Backend health returned $status" >&2
    exit 1
fi

exit 0
