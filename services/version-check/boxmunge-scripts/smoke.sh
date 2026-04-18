#!/usr/bin/env bash
set -euo pipefail

# Verify the version-check endpoint responds with valid JSON
resp=$(curl -sf "http://boxmunge-web-web:8147/v1/check?v=0.0.0" 2>/dev/null) || {
    echo "FAIL: /v1/check endpoint unreachable" >&2
    exit 1
}

# Check that response contains expected fields
echo "$resp" | python3 -c "
import json, sys
data = json.load(sys.stdin)
assert 'status' in data, 'missing status field'
assert 'security' in data, 'missing security field'
assert 'latest' in data, 'missing latest field'
" || {
    echo "FAIL: /v1/check response missing required fields" >&2
    exit 1
}

echo "OK: version-check service healthy"
exit 0
