#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/crowdsec-acquis.sh — the CrowdSec acquisition boxmunge manages.
# Run by install.sh on every install and upgrade, once Caddy is up; idempotent.
#
# Checks boxmunge-caddy is the system Caddy, writes the Caddy acquisition and
# parser and the crowdsec unit's limits, removes the file acquisition earlier
# releases appended to acquis.yaml, corrects the SSH filter they appended,
# installs the HTTP scenarios if missing, restarts CrowdSec and checks that it
# tails boxmunge-caddy and parses a Caddy access line into those scenarios.
# Anything short of that exits non-zero: a CrowdSec that silently reads
# nothing is worse than a failed install.
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
CADDY_COMPOSE="${BOXMUNGE_ROOT:-/opt/boxmunge}/caddy/compose.yml"
ACQUIS=/etc/crowdsec/acquis.d/boxmunge-caddy.yaml
PARSER=/etc/crowdsec/parsers/s01-parse/boxmunge-caddy-logs.yaml
LEGACY_ACQUIS=/etc/crowdsec/acquis.yaml
LEGACY_LOG="${BOXMUNGE_ROOT:-/opt/boxmunge}/caddy/logs/access.log"
DROPIN=/etc/systemd/system/crowdsec.service.d/boxmunge-limits.conf
CROWDSEC_LOG=/var/log/crowdsec.log
VERIFY_SECONDS=60

# A Caddy access line as boxmunge's site config logs it, from a TEST-NET address
# (not whitelisted) with a scanner's User-Agent, which a scenario must see.
SAMPLE='{"level":"info","ts":1792200000.5,"logger":"http.log.access.log0","msg":"handled request","request":{"remote_ip":"192.0.2.10","remote_port":"40000","client_ip":"192.0.2.10","proto":"HTTP/1.1","method":"GET","host":"example.com","uri":"/"},"bytes_read":0,"user_id":"","duration":0.0001,"size":2,"status":200,"user_agent":"Nikto/2.5.0"}'

fail() { echo "ERROR: $*" >&2; exit 1; }

write_acquisition() {
    install -d -m 755 "$(dirname "${ACQUIS}")"
    # stdout only: Caddy's own runtime log (stderr) is not an access log.
    cat > "${ACQUIS}.tmp" <<YAML
# Managed by boxmunge (bootstrap/crowdsec-acquis.sh); rewritten on upgrade.
source: docker
container_name:
  - ${CADDY_CONTAINER}
follow_stdout: true
follow_stderr: false
labels:
  type: boxmunge-caddy
YAML
    chmod 644 "${ACQUIS}.tmp"
    mv -f "${ACQUIS}.tmp" "${ACQUIS}"
}

# The hub's crowdsecurity/caddy-logs only parses a line that logs the request
# headers, which boxmunge's Caddy does not (a client sets them, at any length:
# see caddy.py). This parser reads the bounded fields Caddy does log, the
# User-Agent among them, into what the hub's HTTP enricher and scenarios use.
# Its type is boxmunge's own, so the hub parser never sees these lines.
write_parser() {
    install -d -m 755 "$(dirname "${PARSER}")"
    cat > "${PARSER}.tmp" <<'YAML'
# Managed by boxmunge (bootstrap/crowdsec-acquis.sh); rewritten on upgrade.
filter: "evt.Parsed.program == 'boxmunge-caddy'"
onsuccess: next_stage
name: boxmunge/caddy-logs
description: "Parse boxmunge's Caddy access log (bounded fields, no headers)"
statics:
  - meta: log_type
    value: http_access-log
  - meta: service
    value: http
  - meta: source_ip
    expression: JsonExtract(evt.Line.Raw, "request.remote_ip")
  - meta: http_status
    expression: JsonExtract(evt.Line.Raw, "status")
  - meta: http_path
    expression: JsonExtract(evt.Line.Raw, "request.uri")
  - target: evt.Parsed.request
    expression: JsonExtract(evt.Line.Raw, "request.uri")
  - parsed: verb
    expression: JsonExtract(evt.Line.Raw, "request.method")
  - meta: http_verb
    expression: JsonExtract(evt.Line.Raw, "request.method")
  - parsed: http_user_agent
    expression: JsonExtract(evt.Line.Raw, "user_agent")
  - meta: http_user_agent
    expression: JsonExtract(evt.Line.Raw, "user_agent")
  - meta: target_fqdn
    expression: JsonExtract(evt.Line.Raw, "request.host")
YAML
    chmod 644 "${PARSER}.tmp"
    mv -f "${PARSER}.tmp" "${PARSER}"
}

# The docker source follows a container by name. A container of that name that
# is not the one caddy/compose.yml made (a project cannot name one so, see
# compose_isolation) would feed CrowdSec lines of its choosing.
require_system_caddy() {
    local config
    config="$(docker inspect --format \
        '{{index .Config.Labels "com.docker.compose.project.config_files"}}' \
        "${CADDY_CONTAINER}")" \
        || fail "there is no ${CADDY_CONTAINER} container; start it with
       docker compose -f ${CADDY_COMPOSE} up -d"
    [[ "${config}" == "${CADDY_COMPOSE}" ]] \
        || fail "${CADDY_CONTAINER} was not made from ${CADDY_COMPOSE} (its compose
       file is '${config}'). Remove it and run: docker compose -f ${CADDY_COMPOSE} up -d"
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

# Earlier bootstraps appended this filter where acquis.yaml had no journal
# source; Debian's unit is ssh.service, so it matched nothing.
fix_ssh_filter() {
    [[ -f "${LEGACY_ACQUIS}" ]] || return 0
    sed -i 's/^  - "_SYSTEMD_UNIT=sshd\.service"$/  - "_SYSTEMD_UNIT=ssh.service"/' "${LEGACY_ACQUIS}"
    if grep -qF "_SYSTEMD_UNIT=sshd.service" "${LEGACY_ACQUIS}"; then
        fail "${LEGACY_ACQUIS} filters the journal on sshd.service, which Debian does not
       have (its unit is ssh.service). Correct that entry by hand and run this again."
    fi
}

# The HTTP enricher and scenarios come with crowdsecurity/caddy. An install
# whose collection step failed (crowdsec.sh used to hide that) never got them.
# Only then is the hub contacted: an outage must not fail every upgrade, nor
# --force overwrite what the operator adjusted. The hub index must be current
# for the install to succeed.
install_scenarios() {
    local installed
    installed="$(cscli collections list -o raw)"
    if ! grep -q '^crowdsecurity/caddy,' <<<"${installed}"; then
        cscli hub update
        cscli collections install crowdsecurity/caddy
    fi
}

# MemoryMax bounds what a flood of lines can make CrowdSec hold; GOMEMLIMIT
# makes Go collect before reaching it; Restart brings it back if it is killed,
# so hitting the bound never switches detection off for good.
write_limits() {
    install -d -m 755 "$(dirname "${DROPIN}")"
    cat > "${DROPIN}.tmp" <<'UNIT'
# Managed by boxmunge (bootstrap/crowdsec-acquis.sh); rewritten on upgrade.
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

# Whether CrowdSec logged, after byte offset $1 of its log, that it tails Caddy.
# Process substitution, not a pipe: grep -q exiting early would SIGPIPE tail
# and, under pipefail, read as no match. Until CrowdSec first starts the log
# may not exist; the caller's timeout reports that.
tails_caddy() {
    grep -qF "start tail for container ${CADDY_CONTAINER}\"" \
        < <(tail -c "+$(($1 + 1))" "${CROWDSEC_LOG}" 2>/dev/null)
}

restart_and_verify() {
    local offset size
    offset="$(stat -c %s "${CROWDSEC_LOG}" 2>/dev/null || echo 0)"
    systemctl restart crowdsec
    local deadline=$((SECONDS + VERIFY_SECONDS))
    until tails_caddy "${offset}"; do
        if (( SECONDS >= deadline )); then
            fail "CrowdSec is not reading ${CADDY_CONTAINER}'s access log: ${CROWDSEC_LOG}
       shows no 'start tail for container ${CADDY_CONTAINER}' within ${VERIFY_SECONDS}s
       of the restart. Is ${CADDY_CONTAINER} running (docker ps)? Check
       ${CROWDSEC_LOG} for the docker datasource's errors."
        fi
        sleep 1
        # CrowdSec rotated its log: the new file holds only lines since then.
        size="$(stat -c %s "${CROWDSEC_LOG}" 2>/dev/null || echo 0)"
        (( size >= offset )) || offset=0
    done
    local out
    out="$(cscli explain --log "${SAMPLE}" --type boxmunge-caddy --color no 2>&1)" \
        || fail "cscli explain failed: ${out}"
    if ! grep -qF "🟢 boxmunge/caddy-logs" <<<"${out}" \
            || ! grep -qF "parser success" <<<"${out}" \
            || ! grep -qF "🟢 crowdsecurity/http-bad-user-agent" <<<"${out}"; then
        fail "CrowdSec does not parse Caddy's access log into its HTTP scenarios
       (${PARSER}, crowdsecurity/caddy). cscli explain said:
${out}"
    fi
    echo "  CrowdSec tails ${CADDY_CONTAINER} and parses its access log"
}

require_system_caddy
write_acquisition
write_parser
remove_legacy_acquisition
fix_ssh_filter
install_scenarios
write_limits
restart_and_verify
