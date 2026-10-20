#!/bin/sh
# Runs inside the web container (python:3.12-slim has no wget or curl).
SERVICE="$1"
if [ "$SERVICE" = "web" ]; then
    exec python3 -c '
import sys, urllib.request
for path in ("/healthz", "/version"):
    try:
        with urllib.request.urlopen("http://localhost:8080" + path, timeout=5) as r:
            if r.status != 200:
                sys.exit(f"GET {path}: HTTP {r.status}")
    except Exception as e:
        sys.exit(f"GET {path}: {e}")
'
fi
exit 0
