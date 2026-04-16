#!/bin/sh
SERVICE="$1"
if [ "$SERVICE" = "web" ]; then
    wget -qO- http://localhost:8080/healthz > /dev/null 2>&1
    exit $?
fi
exit 0
