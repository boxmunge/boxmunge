#!/usr/bin/env bash
# tests/shim/test_guide_verb.sh — `guide <version>`: a newer release's
# upgrade-notes.json, printed byte for byte only once its own line in the
# release's cosign-signed SHA256SUMS verifies it. Read-only: no upgrade
# state changes, the cosign failure count included, and nothing is left in
# a scratch directory. Only curl and cosign are stubbed.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016  # SC2016: stub bodies are literal bash
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

FIXTURE="$(mktemp -d)"
mkdir -p "$FIXTURE/bin"
# curl answers --write-out's %{http_code}: 503 while $RELEASE/unavailable
# exists, 404 for a file the release does not have.
cat > "$FIXTURE/bin/curl" <<'EOF'
#!/usr/bin/env bash
echo "curl $*" >> "$BOXMUNGE_ROOT/calls"
f="$RELEASE/$(basename "${@: -1}")"
code=200
[[ -f "$f" ]] || code=404
[[ ! -e "$RELEASE/unavailable" || "$f" != *upgrade-notes.json ]] || code=503
[[ "$*" != *"--write-out"* ]] || printf '%s' "$code"
[[ "$code" == 200 ]] || exit 22
cp "$f" "$3"
EOF
printf '#!/usr/bin/env bash\n[[ ! -e "$BOXMUNGE_ROOT/cosign-fails" ]] || { echo "Error: invalid signature" >&2; exit 1; }\n' > "$FIXTURE/bin/cosign"
# Every scratch directory the shim makes is under here, so none can be left.
mkdir "$FIXTURE/tmp"
chmod +x "$FIXTURE/bin"/*
export PATH="$FIXTURE/bin:$PATH"

# The notes: non-ASCII bytes and no final newline, so only a byte-for-byte
# copy compares equal.
NOTES='{"format": 1, "release": "1.5.0", "floor": "0.11.0", "entries": [{"title": "café — résumé"}]}'

# release <sums>: 1.5.0's signed release; <sums> lists the notes (good), omits
# them (missing), or lists another hash (tampered).
release() {
    RELEASE="$(mktemp -d)"
    export RELEASE
    printf '%s' "$NOTES" > "$RELEASE/upgrade-notes.json"
    printf 'café' >> "$RELEASE/upgrade-notes.json"
    echo bundle > "$RELEASE/boxmunge-1.5.0.tar.gz"
    (cd "$RELEASE" && sha256sum boxmunge-1.5.0.tar.gz > SHA256SUMS)
    case "$1" in
        good) (cd "$RELEASE" && sha256sum upgrade-notes.json >> SHA256SUMS) ;;
        tampered) echo "$(printf 'a%.0s' {1..64})  upgrade-notes.json" >> "$RELEASE/SHA256SUMS" ;;
    esac
    touch "$RELEASE/SHA256SUMS.sig" "$RELEASE/SHA256SUMS.cert"
}

box() {
    new_root a
    echo "1.4.0" > "$BOXMUNGE_ROOT/config/version"
    mkdir -m 0700 "$BOXMUNGE_ROOT/upgrade-root"
    printf '{"1.5.0": 1}' > "$BOXMUNGE_ROOT/upgrade-root/cosign-failures.json"
    : > "$BOXMUNGE_ROOT/calls"
}

# guide <args...>: stdout to $BOXMUNGE_ROOT/stdout (bytes), stderr to ERR.
guide() {
    RC=0
    TMPDIR="$FIXTURE/tmp" bash "$SHIM" guide "$@" > "$BOXMUNGE_ROOT/stdout" 2> "$BOXMUNGE_ROOT/stderr" || RC=$?
    ERR="$(cat "$BOXMUNGE_ROOT/stderr")"
}

# refused <rc> <in stderr> <description>: nothing on stdout, the cosign count
# untouched and no scratch left.
refused() {
    if [[ "$RC" -eq "$1" && ! -s "$BOXMUNGE_ROOT/stdout" && "$ERR" == *"$2"* \
            && "$(cat "$BOXMUNGE_ROOT/upgrade-root/cosign-failures.json")" == '{"1.5.0": 1}' \
            && -z "$(ls -A "$FIXTURE/tmp")" ]]; then
        pass "$3"
    else
        fail "$3 (rc=$RC, want $1 and '$2'; stdout: $(head -c 200 "$BOXMUNGE_ROOT/stdout"); stderr: $ERR; tmp: $(ls -A "$FIXTURE/tmp"))"
    fi
}

release good
box
guide 1.5.0
cmp -s "$BOXMUNGE_ROOT/stdout" "$RELEASE/upgrade-notes.json" && [[ "$RC" -eq 0 ]] \
    && pass "guide prints the verified notes byte for byte" || fail "guide: rc=$RC $ERR"
[[ "$(cat "$BOXMUNGE_ROOT/upgrade-root/cosign-failures.json")" == '{"1.5.0": 1}' && -z "$(ls -A "$FIXTURE/tmp")" ]] \
    && pass "a guide leaves the cosign count and no scratch" || fail "after guide: $(ls -A "$FIXTURE/tmp")"
grep -q "curl .*--max-filesize 1048576 .*/v1.5.0/upgrade-notes.json$" "$BOXMUNGE_ROOT/calls" \
    && pass "the notes download is capped at 1 MiB" || fail "calls: $(cat "$BOXMUNGE_ROOT/calls")"
grep -q "boxmunge-1.5.0.tar.gz" "$BOXMUNGE_ROOT/calls" && fail "the guide downloaded the bundle" \
    || pass "a guide downloads no bundle"
touch "$BOXMUNGE_ROOT/cosign-fails"
guide 1.5.0
refused 1 "Cosign verification of SHA256SUMS FAILED, refusing to install: Error: invalid signature" \
    "guide refuses a bad signature and leaves cosign-failures.json untouched"
drop_root

# The version: a newer one, from the first release that has notes on.
box
for v in 1.4.0 1.3.0 1.4.0-rc.1; do
    guide "$v"
    refused 1 "this box runs 1.4.0, and they are for a newer release; run upgrade-howto" "guide refuses $v (not newer)"
done
echo "0.11.6" > "$BOXMUNGE_ROOT/config/version"
guide 0.11.7
refused 1 "0.11.7 has no upgrade notes: releases publish them from 0.11.8 on; run upgrade-howto" \
    "guide refuses a release from before upgrade notes"
[[ ! -s "$BOXMUNGE_ROOT/calls" ]] && pass "a refused version downloads nothing" || fail "calls: $(cat "$BOXMUNGE_ROOT/calls")"
drop_root
rm -rf "$RELEASE"

release missing
box
guide 1.5.0
refused 1 "Checksum verification FAILED: SHA256SUMS does not list upgrade-notes.json" "guide refuses notes missing from SHA256SUMS"
drop_root
rm -rf "$RELEASE"

release tampered
box
guide 1.5.0
refused 1 "Checksum verification FAILED (upgrade-notes.json of 1.5.0)" "guide refuses tampered notes"
drop_root

box
rm "$RELEASE/upgrade-notes.json"
guide 1.5.0
refused 1 "Release 1.5.0 publishes no upgrade-notes.json (GitHub answered 404)" "guide says when a release has no notes"
echo notes > "$RELEASE/upgrade-notes.json"
touch "$RELEASE/unavailable"
guide 1.5.0
refused 1 "GitHub refused the download of upgrade-notes.json of 1.5.0 (HTTP 503); retry later" \
    "guide tells an HTTP error from a release without notes"
rm "$RELEASE/unavailable"
head -c 1048577 /dev/zero > "$RELEASE/upgrade-notes.json"
(cd "$RELEASE" && sha256sum boxmunge-1.5.0.tar.gz upgrade-notes.json > SHA256SUMS)
guide 1.5.0
refused 1 "upgrade-notes.json of 1.5.0 is 1048577 bytes, over 1048576; refusing it" "guide refuses notes over 1 MiB"
drop_root
rm -rf "$RELEASE"

rm -rf "$FIXTURE"
finish
