#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap/userns.sh — remap Docker's user namespaces on a fresh install.
# Sourced by init-host.sh before Docker first starts, so the containerd image
# store is never initialised and container uid N is host uid S+N from the
# first container on. Existing boxes migrate with
# `boxmunge-upgrade userns-migrate` instead (OPERATIONS.md).
# Every function that refuses says why on stderr and returns non-zero.

USERNS_NAME="boxmunge-remap"
USERNS_RANGE=65536

_userns_error() {
    echo "ERROR: $*" >&2
    return 1
}

# _userns_subids <file>: its entries, one name:start:count per line. A line
# that is not name:start:count is refused, as offset.read_subids refuses it.
_userns_subids() {
    [[ -e "$1" ]] || return 0
    awk '{ line = $0; gsub(/^[ \t\r]+|[ \t\r]+$/, "", line) }
         line == "" || line ~ /^#/ { next }
         { if (split(line, f, ":") != 3 || f[2] !~ /^[0-9]+$/ || f[3] !~ /^[0-9]+$/) {
               printf "ERROR: %s:%d is not name:start:count: %s\n", FILENAME, FNR, line > "/dev/stderr"
               exit 1 }
           print line }' "$1"
}

# _userns_own <entries>: start:count of each entry that is boxmunge-remap's,
# by name or by its numeric uid (as Docker reads the files), in plain base 10
# as Python's int() reads them (01048576 is 1048576, not octal).
_userns_own() {
    local uid
    uid="$(awk -F: -v n="$USERNS_NAME" '$1 == n && $3 ~ /^[0-9]+$/ {print $3; exit}' /etc/passwd)"
    # ("" ...) forces a string compare: Docker does not read 0999 as uid 999.
    awk -F: -v n="$USERNS_NAME" -v u="$uid" \
        '$1 == n || (u != "" && ($1 "") == (u "")) {printf "%.0f:%.0f\n", $2, $3}' <<<"$1"
}

# userns_allocate: print S. boxmunge-remap's own range when it has exactly one
# aligned range of 65536 at the same start in both files; otherwise the first
# 65536-aligned block >= 1,000,000 that is free in /etc/subuid and /etc/subgid
# and holds no uid or gid in /etc/passwd or /etc/group.
# (Same rule as boxmunge.userns.offset.allocate_offset.)
userns_allocate() {
    local subuid subgid own_u own_g
    subuid="$(_userns_subids /etc/subuid)" || return 1
    subgid="$(_userns_subids /etc/subgid)" || return 1
    own_u="$(_userns_own "$subuid")"
    own_g="$(_userns_own "$subgid")"
    if [[ -n "$own_u$own_g" ]]; then
        if [[ "$own_u" == "$own_g" && "$own_u" != *$'\n'* && "${own_u#*:}" == "$USERNS_RANGE" ]] \
              && (( ${own_u%%:*} % USERNS_RANGE == 0 )); then
            echo "${own_u%%:*}"
            return 0
        fi
        _userns_error "$USERNS_NAME already has subordinate ids other than one aligned range" \
            "of $USERNS_RANGE at the same start in both files (subuid '${own_u//$'\n'/ }'," \
            "subgid '${own_g//$'\n'/ }'). Fix /etc/subuid and /etc/subgid by hand, then run" \
            "init-host.sh again."
        return 1
    fi
    { printf '%s\n%s\n' "$subuid" "$subgid" | awk -F: 'NF == 3 {print $2, $3}'
      awk -F: '$3 ~ /^[0-9]+$/ {print $3, 1}' /etc/passwd /etc/group
    } | awk -v s=1048576 -v c="$USERNS_RANGE" -v max=4294967295 '
        { start[NR] = $1; count[NR] = $2 }
        END {
            for (; s + c - 1 <= max; s += c) {
                free = 1
                for (i in start) if (start[i] < s + c && s < start[i] + count[i]) { free = 0; break }
                if (free) { printf "%.0f\n", s; exit 0 }
            }
            exit 1
        }' || _userns_error "no free block of $USERNS_RANGE subordinate ids above 1,000,000"
}

# userns_identity <S>: the boxmunge-remap user and group, with the one range
# S..S+65535 in both files.
userns_identity() {
    if ! id "$USERNS_NAME" >/dev/null 2>&1; then
        useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "$USERNS_NAME" \
            || return 1
    fi
    getent group "$USERNS_NAME" >/dev/null \
        || _userns_error "user $USERNS_NAME exists without a group of that name; Docker needs both" \
        || return 1
    local subuid subgid now f
    subuid="$(_userns_subids /etc/subuid)" && subgid="$(_userns_subids /etc/subgid)" || return 1
    if [[ -z "$(_userns_own "$subuid")$(_userns_own "$subgid")" ]]; then
        # Debian 13's passwd package creates neither file, and usermod
        # refuses --add-subuids/--add-subgids without them.
        for f in /etc/subuid /etc/subgid; do
            [[ -e "$f" || -L "$f" ]] || install -m 644 -o root -g root /dev/null "$f" || return 1
        done
        usermod --add-subuids "$1-$(( $1 + USERNS_RANGE - 1 ))" \
            --add-subgids "$1-$(( $1 + USERNS_RANGE - 1 ))" "$USERNS_NAME" || return 1
    fi
    # The range must now be in both files: allocate would also print S for
    # files usermod left empty, so read the entries themselves.
    subuid="$(_userns_subids /etc/subuid)" && subgid="$(_userns_subids /etc/subgid)" || return 1
    now="$(_userns_own "$subuid") / $(_userns_own "$subgid")"
    [[ "$now" == "$1:$USERNS_RANGE / $1:$USERNS_RANGE" ]] \
        || _userns_error "$USERNS_NAME's subordinate ids are '$now', not $1:$USERNS_RANGE in both" \
            "/etc/subuid and /etc/subgid"
}

# A host already running containers or volumes is not a fresh install: its
# data would be stranded in the unremapped root.
userns_refuse_existing_docker() {
    command -v docker >/dev/null 2>&1 || return 0
    docker info >/dev/null 2>&1 \
        || _userns_error "Docker is installed but not answering. Start it (systemctl start docker;" \
            "if it will not start, see journalctl -u docker and /etc/docker/daemon.json) so" \
            "init-host.sh can check that it holds no containers or volumes" || return 1
    local containers volumes
    containers="$(docker ps -aq)" && volumes="$(docker volume ls -q)" || return 1
    [[ -z "$containers$volumes" ]] \
        || _userns_error "this host already has Docker containers or volumes; init-host.sh expects" \
            "a fresh host. Migrate an existing boxmunge box with: boxmunge-upgrade userns-migrate"
}

_userns_daemon_json_text() {
    cat <<EOF
{
    "log-driver": "json-file",
    "log-opts": {"max-size": "50m", "max-file": "5"},
    "userns-remap": "$USERNS_NAME:$USERNS_NAME",
    "storage-driver": "overlay2",
    "features": {"containerd-snapshotter": false}
}
EOF
}

# userns_daemon_json_check: a daemon.json already there that says anything
# else is the operator's: it is refused, never overwritten.
userns_daemon_json_check() {
    local path=/etc/docker/daemon.json
    [[ -e "$path" || -L "$path" ]] || return 0
    [[ "$(cat "$path")" == "$(_userns_daemon_json_text)" ]] && return 0
    _userns_error "$path already exists and is not the one init-host.sh writes:" \
        "$(tr '\n' ' ' < "$path"). Move it aside and run init-host.sh again; add your" \
        "settings back afterwards."
}

userns_daemon_json() {
    local path=/etc/docker/daemon.json
    userns_daemon_json_check || return 1
    # 0644 whatever root's umask: deploy reads it (offset.daemon_json_userns).
    install -d -m 755 /etc/docker && _userns_daemon_json_text > "$path" && chmod 644 "$path"
}

# userns_preflight: every refusal, before init-host changes anything; sets
# USERNS_OFFSET (allocating also refuses malformed subid files).
userns_preflight() {
    userns_refuse_existing_docker && userns_daemon_json_check || return 1
    USERNS_OFFSET="$(userns_allocate)"
}

# userns_before_docker: the identity, then daemon.json, before Docker's first
# start, so a daemon.json is never left naming an identity that is not there.
userns_before_docker() {
    userns_identity "$USERNS_OFFSET" && userns_daemon_json
}

# userns_verify <S>: the running daemon is remapped as daemon.json says.
userns_verify() {
    local info opts driver root
    info="$(docker info --format '{{json .SecurityOptions}}|{{.Driver}}|{{.DockerRootDir}}')" \
        || return 1
    IFS='|' read -r opts driver root <<<"$info"
    [[ "$opts" == *'"name=userns"'* && "$driver" == overlay2 && "$root" == "/var/lib/docker/$1.$1" ]] \
        || _userns_error "Docker did not come up remapped on overlay2 as daemon.json says" \
            "(security options $opts, driver $driver, root dir $root)"
}

# userns_record <S>: append the record boxmunge.userns.offset reads.
userns_record() {
    local cfg="${BOXMUNGE_ROOT}/config/boxmunge.yml"
    if grep -q '^userns:' "$cfg"; then
        _userns_error "$cfg already has a userns record"
        return 1
    fi
    printf 'userns:\n  name: %s\n  offset: %s\n' "$USERNS_NAME" "$1" >> "$cfg"
}

# userns_journal_committed <S>: a fresh install is born committed, so the
# migration finds nothing to do. The format is the migration journal's
# (version 1; direction, phase, offset, fresh_install).
userns_journal_committed() {
    local dir="${BOXMUNGE_ROOT}/upgrade-root"
    if [[ -L "$dir" ]]; then
        _userns_error "$dir is a link; remove it and run init-host.sh again"
        return 1
    fi
    install -d -m 700 -o root -g root "$dir" || return 1
    ( umask 077
      printf '{"version": 1, "direction": "forward", "phase": "committed", "offset": %s, "fresh_install": true}\n' \
          "$1" > "$dir/userns-migration.json.tmp" ) || return 1
    mv -f "$dir/userns-migration.json.tmp" "$dir/userns-migration.json"
}
