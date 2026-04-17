#!/bin/sh
SERVICE="$1"
if [ "$SERVICE" = "web" ]; then
    wget -qO- http://localhost:8080/healthz > /dev/null 2>&1 || exit 1
    wget -qO- http://localhost:8080/version > /dev/null 2>&1 || exit 1
    exit 0
fi
exit 0
