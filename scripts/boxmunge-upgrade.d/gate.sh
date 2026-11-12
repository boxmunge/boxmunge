# shellcheck shell=bash
# gate.sh — an upgrade that crosses a breaking release runs the target's
# readiness check first, and installs only when it passes; and after any
# upgrade, the to-do alert: what each project must change before its next
# deploy. Security and break-fix releases are non-breaking by definition, so
# they install ungated (one unready project must not hold a fix hostage for
# the whole box), and the to-do alert tells what their new rules ask.
# Whether an upgrade crosses a breaking release is read from the target's
# own signed upgrade-notes.json, never from the unsigned discovery answer.
# Every mode but force is gated: run as well, which deploy's `upgrade`
# (auto) uses. The operator's force-target is the override.
# Part of boxmunge-upgrade (runs as root); scripts/build-shim.py inlines it into
# the shim that releases ship.

# GATE: 1 while the upgrade in progress crosses a breaking release.
GATE=0

# gate_prepare <version> <mode> <dir> <from_version>: decide GATE, before the
# standby is built. <dir> holds the release fetch_release verified; its
# upgrade-notes.json must be the one its signed SHA256SUMS lists, or the
# upgrade fails its pre-flight (and <version> is blocklisted) as for a bad
# bundle. A crossing upgrade then needs the bundle's prerequisites met, or
# it is refused, unblocklisted (gate_refused).
gate_prepare() {
    local version="$1" mode="$2" dir="$3" from_version="$4" notes="$3/upgrade-notes.json" breaking rc=0
    GATE=0
    [[ "$mode" != force ]] || return 0
    ! semver_lt "$version" "$FIRST_NOTES_RELEASE" || return 0
    download "$notes" "$(release_url "$version" upgrade-notes.json)" --max-filesize "$NOTES_MAX_BYTES" \
        || preflight_fail "$version" "$from_version" "preflight_failed: notes_download" \
            "Failed to download upgrade-notes.json of $version"
    [[ "$(wc -c < "$notes" | tr -d ' ')" -le "$NOTES_MAX_BYTES" ]] \
        || preflight_fail "$version" "$from_version" "preflight_failed: notes_download" \
            "upgrade-notes.json of $version is over $NOTES_MAX_BYTES bytes"
    verify_listed "$dir" upgrade-notes.json notes \
        || preflight_fail "$version" "$from_version" "preflight_failed: $FETCH_STEP" "$FETCH_ERROR (upgrade-notes.json)"
    breaking="$(crossing_breaking "$notes" "$(installed_version)" "$version")" \
        || preflight_fail "$version" "$from_version" "preflight_failed: notes_invalid" \
            "The signed upgrade-notes.json of $version cannot be read: $breaking"
    [[ -n "$breaking" ]] || return 0
    GATE=1
    log "The upgrade to $version crosses the breaking release $breaking: $version's readiness check must pass first"
    command -v systemd-run >/dev/null 2>&1 \
        || gate_refused "$version" "this box has no systemd-run, which the readiness check runs in (as supervisor: sudo apt-get install systemd)"
    run_prerequisites "$dir/boxmunge" "$dir/prerequisites.jsonl" || rc=$?
    case "$rc" in
        0) ;;
        1) gate_refused "$version" "this box does not meet what $version needs: $(prerequisites_summary "$dir/prerequisites.jsonl")" ;;
        *) gate_refused "$version" "could not tell whether this box meets what $version needs: $(prerequisites_summary "$dir/prerequisites.jsonl")" ;;
    esac
}

# crossing_breaking <notes> <installed> <target>: the first release I < v <= T
# that the notes' releases table marks breaking, or nothing. Fails, saying
# why, when the notes are not format 1 of <target> with a table holding it,
# every entry's breaking a JSON boolean: the gate is never skipped on a guess.
crossing_breaking() {
    python3 -I -c 'import json, re, sys
path, installed, target = sys.argv[1:4]
semver = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?")
def key(v):
    core, _, pre = v.partition("-")
    nums = tuple(int(x) for x in core.split("."))
    if not pre:
        return nums, 1, ()
    return nums, 0, tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
try:
    with open(path, "rb") as f:
        d = json.loads(f.read())
except (OSError, ValueError, RecursionError) as e:
    sys.exit(f"not JSON ({type(e).__name__})")
if not (isinstance(d, dict) and type(d.get("format")) is int and d["format"] == 1 and d.get("release") == target):
    sys.exit(f"not format 1 of {target}")
releases = d.get("releases")
if not (isinstance(releases, dict) and target in releases and all(
        semver.fullmatch(v) and isinstance(r, dict) and type(r.get("breaking")) is bool for v, r in releases.items())):
    sys.exit(f"its releases table must hold {target}, each entry with a boolean breaking")
crossed = sorted((key(v), v) for v, r in releases.items() if r["breaking"] and key(installed) < key(v) <= key(target))
print(crossed[0][1] if crossed else "")' "$@" 2>&1
}

# prerequisites_summary <jsonl>: the unmet prerequisites, one line of at most
# 400 printable characters.
prerequisites_summary() {
    python3 -I -c "$PY_CLEAN"'
import json, sys
lines = [json.loads(line) for line in open(sys.argv[1])]
print(clean("; ".join(p["script"] + ": " + p["message"] for p in lines if not p["ok"]), 400))' "$1"
}

# gate_readiness <version> <standby>: with GATE set, the readiness command of
# the release just built into env-<standby> (as deploy, confined) must pass,
# or the upgrade is refused. Run in the pre-flight before the release's own
# dry run, so a box the dry run would refuse is refused here, unblocklisted.
gate_readiness() {
    local version="$1" out="$TMP_DOWNLOAD/readiness.json" rc=0 verdict
    [[ "$GATE" -eq 1 ]] || return 0
    log "Running the readiness check of $version against this box..."
    run_readiness "$BOXMUNGE_ROOT/env-$2" "$out" || rc=$?
    verdict="$(readiness_verdict "$out" "$rc")"
    case "$rc:$verdict" in
        *:pass) log "The readiness check of $version passed"; return 0 ;;
        *:blocked) gate_refused "$version" "its readiness check found what blocks it: $(readiness_summary "$out")" ;;
        124:*) gate_refused "$version" "its readiness check did not finish within $READINESS_SECS s, so this box could not be verified; retry when it is less busy" ;;
        *) gate_refused "$version" "its readiness check gave no valid answer (exit $rc), so this box could not be verified: $(clean_file "$out.err" 300)" ;;
    esac
}

# clean_file <file> <limit>: the end of <file> as one printable line.
clean_file() {
    python3 -I -c "$PY_CLEAN"'
import sys
with open(sys.argv[1], "rb") as f:
    print(clean(f.read().decode("utf-8", "replace"), int(sys.argv[2]), tail=True))' "$1" "$2"
}

# gate_refused <version> <why>: stop the upgrade before anything changed. Not
# the release's failure but the box's state: no blocklist entry and no failure
# report; the standby is dropped and the operator alerted.
gate_refused() {
    local version="$1" msg
    msg="Not upgrading to $version: $2. Nothing was changed and $version is not blocklisted. See what to fix: upgrade-check --version $version (deploy shell). The operator can override as supervisor: sudo $BIN_DIR/boxmunge-upgrade force-target $version"
    remove_slot "$(standby_slot)"
    bm_log warn upgrade "upgrade refused: box not ready" "{\"version\": \"$version\"}"
    send_notification "boxmunge upgrade to $version refused" "$msg" 0
    die "$msg"
}

# post_install_todo <version>: once <version> is live and on probation, its
# readiness command (as deploy, confined) lists what each project must
# change before its next deploy, as one low-priority alert; "blocked" is a
# release bug (the upgrade went ahead), said at normal priority. It can
# neither fail nor roll back the upgrade: whatever goes wrong is a warning.
post_install_todo() {
    local version="$1" out="$TMP_DOWNLOAD/todo.json" rc=0 verdict alert priority title
    ! semver_lt "$version" "$FIRST_NOTES_RELEASE" || return 0
    if ! command -v systemd-run >/dev/null 2>&1; then
        log "WARN: no systemd-run, so no to-do list for $version's projects"
        return 0
    fi
    run_readiness "$(active_venv)" "$out" || rc=$?
    verdict="$(readiness_verdict "$out" "$rc")"
    if [[ "$verdict" == invalid ]] || ! alert="$(todo_alert "$version" "$out")"; then
        log "WARN: the readiness check of $version gave no to-do list (exit $rc); run validate <project> before deploying each project"
        bm_log warn upgrade "post-install to-do list unavailable" "{\"version\": \"$version\", \"exit\": $rc}"
        return 0
    fi
    [[ -n "$alert" ]] || return 0
    priority="${alert%%$'\n'*}"
    alert="${alert#*$'\n'}"
    title="${alert%%$'\n'*}"
    send_notification "$title" "${alert#*$'\n'}" "$priority"
}

# todo_alert <version> <answer>: the to-do alert as its priority, title and
# body, one a line (the body over several), or nothing when there is nothing
# to do.
todo_alert() {
    python3 -I -c "$PY_CLEAN"'
import json, sys
version = sys.argv[1]
with open(sys.argv[2], "rb") as f:
    d = json.loads(f.read())
def todos(findings):
    return [f for f in findings if isinstance(f, dict) and f.get("severity") == "todo"] if isinstance(findings, list) else []
if d["result"] == "blocked":
    print(0, f"boxmunge {version}: readiness reports blocked (a boxmunge bug)", sep="\n")
    print(f"{version} is installed, but its own readiness check reports the box blocked, which an installed release must never do. Report it as a boxmunge bug, with the output of: boxmunge-server upgrade-readiness")
    sys.exit()
lines = []
for name, findings in [("box", d.get("box"))] + [(p.get("name"), p.get("findings")) for p in d.get("projects") or [] if isinstance(p, dict)]:
    first = todos(findings)[:1]
    if first:
        lines.append(clean(str(name) + ": " + str(first[0].get("message")) + " (" + str(first[0].get("remedy")) + ")", 300))
if lines:
    print(-1, f"boxmunge {version}: project to-dos before their next deploy", *lines, sep="\n")
    print("Run validate <project> before deploying each one.")' "$1" "$2"
}
