#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/crowdsec-caddy.sh — CrowdSec reads Caddy's access log from Docker.
# Run by install.sh on every install and upgrade, once Caddy is up; idempotent.
#
# Writes boxmunge's acquisition and the crowdsec unit's limits, removes the file
# acquisition earlier releases appended to acquis.yaml, restarts CrowdSec and
# checks that it tails boxmunge-caddy and parses a Caddy access line. Anything
# short of that exits non-zero: a CrowdSec that silently reads nothing is worse
# than a failed install.
#
# Why the Docker API and not a file: Caddy runs remapped and owns any directory
# it logs into, so it decides what such a file is (a FIFO, /dev/zero, a link to
# a root-only file), and root CrowdSec would open and follow it. Through the
# Docker API CrowdSec receives lines dockerd framed (16 KiB at most each) and
# opens nothing Caddy controls. Not journald: under an HTTP flood its rate limit
# would drop exactly the lines CrowdSec needs, and the access log would push
# sshd and kernel history out of the journal.
set -euo pipefail

CADDY_CONTAINER=boxmunge-caddy
ACQUIS=/etc/crowdsec/acquis.d/boxmunge-caddy.yaml
LEGACY_ACQUIS=/etc/crowdsec/acquis.yaml
LEGACY_LOG="${BOXMUNGE_ROOT:-/opt/boxmunge}/caddy/logs/access.log"
DROPIN=/etc/systemd/system/crowdsec.service.d/boxmunge-limits.conf
CROWDSEC_LOG=/var/log/crowdsec.log
VERIFY_SECONDS=60

# A Caddy access line from a TEST-NET address (not whitelisted), as Caddy logs it.
SAMPLE='{"level":"info","ts":1792200000.5,"logger":"http.log.access.log0","msg":"handled request","request":{"remote_ip":"192.0.2.10","remote_port":"40000","client_ip":"192.0.2.10","proto":"HTTP/1.1","method":"GET","host":"example.com","uri":"/","headers":{"User-Agent":["curl/8.0"]}},"bytes_read":0,"user_id":"","duration":0.0001,"size":2,"status":200,"resp_headers":{}}'

fail() { echo "ERROR: $*" >&2; exit 1; }

write_acquisition() {
    install -d -m 755 "$(dirname "${ACQUIS}")"
    # stdout only: Caddy's own runtime log (stderr) is not an access log.
    cat > "${ACQUIS}.tmp" <<YAML
# Managed by boxmunge (bootstrap/crowdsec-caddy.sh); rewritten on upgrade.
source: docker
container_name:
  - ${CADDY_CONTAINER}
follow_stdout: true
follow_stderr: false
labels:
  type: caddy
YAML
    chmod 644 "${ACQUIS}.tmp"
    mv -f "${ACQUIS}.tmp" "${ACQUIS}"
}

# crowdsec.sh used to append exactly this block; nothing else of ours is there.
remove_legacy_acquisition() {
    [[ -f "${LEGACY_ACQUIS}" ]] || return 0
    LEGACY_LOG="${LEGACY_LOG}" perl -0777 -i -pe \
        's/\n---\nsource: file\nfilenames:\n  - \Q$ENV{LEGACY_LOG}\E\nlabels:\n  type: caddy\n//g' \
        "${LEGACY_ACQUIS}"
    if grep -qF "caddy/logs" "${LEGACY_ACQUIS}"; then
        fail "${LEGACY_ACQUIS} still reads a file under caddy/logs, which the remapped
       Caddy controls. Remove that entry by hand (CrowdSec reads Caddy through
       ${ACQUIS} now), then run the install or upgrade again."
    fi
}

# MemoryMax bounds what a flood of lines can make CrowdSec hold; GOMEMLIMIT
# makes Go collect before reaching it; Restart brings it back if it is killed,
# so hitting the bound never switches detection off for good.
write_limits() {
    install -d -m 755 "$(dirname "${DROPIN}")"
    cat > "${DROPIN}.tmp" <<'UNIT'
# Managed by boxmunge (bootstrap/crowdsec-caddy.sh); rewritten on upgrade.
[Service]
MemoryMax=512M
TasksMax=256
Environment=GOMEMLIMIT=400MiB
Restart=on-failure
RestartSec=5s
UNIT
    chmod 644 "${DROPIN}.tmp"
    mv -f "${DROPIN}.tmp" "${DROPIN}"
    systemctl daemon-reload
}

restart_and_verify() {
    local offset
    offset="$(stat -c %s "${CROWDSEC_LOG}" 2>/dev/null || echo 0)"
    systemctl restart crowdsec
    local deadline=$((SECONDS + VERIFY_SECONDS))
    until tail -c "+$((offset + 1))" "${CROWDSEC_LOG}" 2>/dev/null \
            | grep -qF "start tail for container ${CADDY_CONTAINER}\""; do
        if (( SECONDS >= deadline )); then
            fail "CrowdSec is not reading ${CADDY_CONTAINER}'s access log: ${CROWDSEC_LOG}
       shows no 'start tail for container ${CADDY_CONTAINER}' within ${VERIFY_SECONDS}s
       of the restart. Is ${CADDY_CONTAINER} running (docker ps)? Check
       ${CROWDSEC_LOG} for the docker datasource's errors."
        fi
        sleep 1
    done
    local out
    out="$(cscli explain --log "${SAMPLE}" --type caddy --color no 2>&1)" \
        || fail "cscli explain failed: ${out}"
    if ! grep -qF "🟢 crowdsecurity/caddy-logs" <<<"${out}" \
            || ! grep -qF "parser success" <<<"${out}"; then
        fail "CrowdSec does not parse Caddy's access log. Install the parser with
       'cscli collections install crowdsecurity/caddy' and run this again.
       cscli explain said:
${out}"
    fi
    echo "  CrowdSec tails ${CADDY_CONTAINER} and parses its access log"
}

write_acquisition
remove_legacy_acquisition
write_limits
restart_and_verify
