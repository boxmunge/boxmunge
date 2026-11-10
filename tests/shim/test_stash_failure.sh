#!/usr/bin/env bash
# tests/shim/test_stash_failure.sh — a refused or failed platform stash stops
# the upgrade before anything changes, and an unattended auto-update must not
# fail there silently: the shim logs the error, alerts the operator locally
# and drops the half-built standby venv, without blocklisting or reporting
# the release (a stray symlink on the box is not the release's fault).
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016  # SC2016: stub bodies are literal bash
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

# Stand-ins: curl serves a local 1.5.0 release, cosign and sha256sum accept
# it, and python3 -m venv copies in a mock venv that passes preflight.
FIXTURE="$(mktemp -d)"
REAL_PYTHON3="$(command -v python3)"
mkdir -p "$FIXTURE/bin" "$FIXTURE/venv/bin"
stub() {  # stub <path> <bash body>
    printf '#!/usr/bin/env bash\n%s\n' "$2" > "$1"
    chmod +x "$1"
}
stub "$FIXTURE/bin/python3" "if [[ \"\$1 \$2\" == '-m venv' ]]; then mkdir -p \"\$3\"; cp -R '$FIXTURE/venv/bin' \"\$3/\"; exit 0; fi
exec '$REAL_PYTHON3' \"\$@\""
stub "$FIXTURE/bin/curl" 'cp "$RELEASE/$(basename "${@: -1}")" "$3"'
stub "$FIXTURE/bin/cosign" 'exit 0'
stub "$FIXTURE/bin/sha256sum" 'cat >/dev/null; exit 0'
stub "$FIXTURE/venv/bin/pip" 'exit 0'
stub "$FIXTURE/venv/bin/boxmunge-server" '[[ "$1" != --version ]] || echo "boxmunge 1.5.0"; exit 0'
stub "$FIXTURE/venv/bin/python" '[[ "$1" != "-" ]] || cat >/dev/null
[[ "${2:-}" != *get_build_version* ]] || echo "1.5.0"
exit 0'
export PATH="$FIXTURE/bin:$PATH"

RELEASE="$(mktemp -d)"
export RELEASE
mkdir -p "$RELEASE/boxmunge/on-server"
for f in requirements-build.txt requirements-tui.txt requirements-mcp.txt; do
    echo "${f%.txt}==1" > "$RELEASE/boxmunge/$f"
done
echo "1.5.0 ops" > "$RELEASE/boxmunge/on-server/OPERATIONS.md"
tar czf "$RELEASE/boxmunge-1.5.0.tar.gz" -C "$RELEASE" boxmunge
echo "0000  boxmunge-1.5.0.tar.gz" > "$RELEASE/SHA256SUMS"
touch "$RELEASE/SHA256SUMS.sig" "$RELEASE/SHA256SUMS.cert"

# The live 1.4.0 slot a: its stash refuses, as for a stray symlink. Its
# python records every log line, alert, blocklisting and failure report.
new_root a
echo "1.4.0" > "$BOXMUNGE_ROOT/config/version"
mock_server a 'if [[ "$1 $2" == "stash create" ]]; then
    echo "ERROR: Cannot stash: these are symlinks: /opt/boxmunge/projects/app/secrets.env" >&2
    exit 1
fi
[[ "$1" != --version ]] || echo "boxmunge 1.4.0"; exit 0'
rm "$BOXMUNGE_ROOT/env-a/bin/python"
stub "$BOXMUNGE_ROOT/env-a/bin/python" '[[ "$1" != "-" ]] || cat >/dev/null
echo "a-python: level=${BM_LEVEL:-} logmsg=${BM_MSG:-} title=${BM_TITLE:-} msg=${BM_MESSAGE:-} reason=${BM_REASON:-} stage=${BM_STAGE:-} $*" >> "$BOXMUNGE_ROOT/calls"'
: > "$BOXMUNGE_ROOT/calls"
calls() { cat "$BOXMUNGE_ROOT/calls"; }

run_shim target 1.5.0
expect 1 "Cannot stash: these are symlinks" "a refused stash fails the upgrade, showing why"
[[ "$(readlink "$BOXMUNGE_ROOT/env-active")" == *env-a && ! -e "$BOXMUNGE_ROOT/env-b" ]] \
    && pass "the proven slot stays live and the half-built standby is dropped" \
    || fail "live=$(readlink "$BOXMUNGE_ROOT/env-active"), env-b exists: $([[ -e "$BOXMUNGE_ROOT/env-b" ]] && echo yes || echo no)"
grep -q "level=error logmsg=upgrade to 1.5.0 aborted before any change: stash creation failed: ERROR: Cannot stash" "$BOXMUNGE_ROOT/calls" \
    && pass "the failure is logged as an error" || fail "no error log line: $(calls)"
grep -q "title=boxmunge upgrade failed msg=The platform stash failed, so the upgrade to 1.5.0 stopped before changing anything (not blocklisted; auto-update will retry it). Fix this and retry: ERROR: Cannot stash" "$BOXMUNGE_ROOT/calls" \
    && pass "the operator is alerted locally" || fail "no local alert: $(calls)"
! grep -q "add_to_blocklist" "$BOXMUNGE_ROOT/calls" && ! grep -q "stage=preflight" "$BOXMUNGE_ROOT/calls" \
    && pass "the release is neither blocklisted nor reported" || fail "blocklisted or reported: $(calls)"
[[ "$(cat "$BOXMUNGE_ROOT/config/version")" == 1.4.0 ]] && pass "the installed version is unchanged" \
    || fail "version is $(cat "$BOXMUNGE_ROOT/config/version")"
drop_root

# A stash create that succeeds but does not say which stash it made leaves
# the rollback nothing it can trust: the upgrade stops there too.
new_root a
echo "1.4.0" > "$BOXMUNGE_ROOT/config/version"
mock_server a 'if [[ "$1 $2" == "stash create" ]]; then echo "done"; exit 0; fi
[[ "$1" != --version ]] || echo "boxmunge 1.4.0"; exit 0'
rm "$BOXMUNGE_ROOT/env-a/bin/python"
stub "$BOXMUNGE_ROOT/env-a/bin/python" '[[ "$1" != "-" ]] || cat >/dev/null; exit 0'
run_shim target 1.5.0
expect 1 "stash create did not name the stash it made" "an unnamed stash stops the upgrade"
[[ "$(readlink "$BOXMUNGE_ROOT/env-active")" == *env-a && ! -e "$BOXMUNGE_ROOT/env-b" ]] \
    && pass "an unnamed stash: the proven slot stays live" || fail "an unnamed stash: live=$(readlink "$BOXMUNGE_ROOT/env-active")"
drop_root

# A stash create without a 'Stash digest:' line (a release before 0.11.6;
# the default mock): the upgrade records the stash it made with the size and
# sha256 of the file, or by name alone when it holds link members (a release
# before 0.10.2 made it), which the new release's apply rewrites away.
for kind in plain links; do
    new_root a
    echo "1.4.0" > "$BOXMUNGE_ROOT/config/version"
    if [[ "$kind" == links ]]; then
        mock_server a 'if [[ "$1 $2" == "stash create" ]]; then
    n=boxmunge-stash-2026-06-01T120000.tar.gz
    python3 -c "import io, tarfile, sys
with tarfile.open(sys.argv[1], \"w:gz\") as t:
    i = tarfile.TarInfo(\"projects/app/manifest.yml\"); i.type = tarfile.SYMTYPE; i.linkname = \"repo/manifest.yml\"; t.addfile(i)" "$BOXMUNGE_ROOT/stashes/$n"
    echo "Stash created: $n"; exit 0
fi
[[ "$1" != --version ]] || echo "boxmunge 1.4.0"; exit 0'
    else
        mock_server a '[[ "$1" != --version ]] || echo "boxmunge 1.4.0"; exit 0'
    fi
    rm "$BOXMUNGE_ROOT/env-a/bin/python"
    stub "$BOXMUNGE_ROOT/env-a/bin/python" '[[ "$1" != "-" ]] || cat >/dev/null; exit 0'
    run_shim target 1.5.0
    expect 0 "probation started" "an upgrade whose stash is $kind completes"
    read -r v name size sha < "$BOXMUNGE_ROOT/upgrade-root/upgrade-stash"
    stash="$BOXMUNGE_ROOT/stashes/$name"
    if [[ "$kind" == plain ]]; then
        want="$("$REAL_PYTHON3" -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$stash")"
        [[ "$v" == 1.5.0 && -f "$stash" && "$size" == "$(wc -c < "$stash" | tr -d ' ')" && "$sha" == "$want" ]] \
            && pass "the stash is recorded with its size and sha256" || fail "record: $v $name $size $sha"
    else
        [[ "$v" == 1.5.0 && -f "$stash" && -z "${size:-}" && -z "${sha:-}" ]] \
            && pass "a stash with link members is recorded by name alone" || fail "record: $v $name ${size:-} ${sha:-}"
        [[ "$OUT" == *"link members"* ]] && pass "and the shim says why" || fail "out: $OUT"
    fi
    drop_root
done

# A stash create that prints the size and sha256 of what it wrote: the shim
# records those, and refuses, before anything changes, a file at the name
# that is not what it wrote (stashes/ is deploy-writable: an older stash
# renamed over the name) or a digest line it cannot read.
STASH_WITH_DIGEST='if [[ "$1 $2" == "stash create" ]]; then
    n=boxmunge-stash-2026-06-01T120000.tar.gz; f="$BOXMUNGE_ROOT/stashes/$n"
    python3 -c "import tarfile, sys; tarfile.open(sys.argv[1], \"w:gz\").close()" "$f"
    echo "Stash created: $n"
    echo "Stash digest: $(python3 -c "import hashlib, os, sys; b = open(sys.argv[1], \"rb\").read(); print(len(b), hashlib.sha256(b).hexdigest())" "$f")"
    case "${STASH_TWIST:-}" in
        renamed-over) mv "$BOXMUNGE_ROOT/stashes/'"$OLD_STASH"'" "$f" ;;
        malformed) echo "Stash digest: 12 nothex" ;;
    esac
    exit 0
fi
[[ "$1" != --version ]] || echo "boxmunge 1.4.0"; exit 0'
for twist in none renamed-over malformed; do
    new_root a
    echo "1.4.0" > "$BOXMUNGE_ROOT/config/version"
    mock_server a "$STASH_WITH_DIGEST"
    rm "$BOXMUNGE_ROOT/env-a/bin/python"
    stub "$BOXMUNGE_ROOT/env-a/bin/python" '[[ "$1" != "-" ]] || cat >/dev/null; exit 0'
    STASH_TWIST="$twist" run_shim target 1.5.0
    stash="$BOXMUNGE_ROOT/stashes/boxmunge-stash-2026-06-01T120000.tar.gz"
    printed="$(sed -n 's/^.*Stash digest: //p' <<< "$OUT" | head -n 1)"
    case "$twist" in
    none)
        expect 0 "probation started" "an upgrade whose stash create prints its digest completes"
        [[ "$(cat "$BOXMUNGE_ROOT/upgrade-root/upgrade-stash")" == "1.5.0 ${stash##*/} $printed" && -n "$printed" ]] \
            && pass "the printed size and sha256 are recorded" \
            || fail "record: $(cat "$BOXMUNGE_ROOT/upgrade-root/upgrade-stash"), printed: $printed" ;;
    renamed-over)
        expect 1 "$stash is not what stash create just wrote" "a file renamed over the stash is refused, naming it"
        [[ "$OUT" == *"boxmunge-upgrade target 1.5.0"* ]] && pass "the refusal names the retry" || fail "out: $OUT" ;;
    malformed)
        expect 1 "stash create printed a digest line the shim cannot read" "an unreadable digest line is refused" ;;
    esac
    if [[ "$twist" != none ]]; then
        [[ "$(readlink "$BOXMUNGE_ROOT/env-active")" == *env-a && ! -e "$BOXMUNGE_ROOT/env-b" \
            && ! -e "$BOXMUNGE_ROOT/upgrade-root/upgrade-stash" && "$(cat "$BOXMUNGE_ROOT/config/version")" == 1.4.0 ]] \
            && pass "$twist: nothing has changed" \
            || fail "$twist: live=$(readlink "$BOXMUNGE_ROOT/env-active"), version $(cat "$BOXMUNGE_ROOT/config/version")"
    fi
    drop_root
done

rm -rf "$FIXTURE" "$RELEASE"
finish
