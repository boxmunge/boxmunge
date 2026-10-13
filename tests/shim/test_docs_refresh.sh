#!/usr/bin/env bash
# tests/shim/test_docs_refresh.sh — on-box docs follow the active release:
# replaced as a whole on install and upgrade, restored on rollback.
# pass() always returns 0, so "cond && pass || fail" is a safe if/else here.
# shellcheck disable=SC2015,SC2016  # SC2016: literal $ strings are intended
set -euo pipefail
# shellcheck source=tests/shim/lib.sh
source "$(dirname "$0")/lib.sh"

docs_src() {  # docs_src <name=content>... -> prints a new dir holding them
    local d
    d="$(mktemp -d)"
    for pair in "$@"; do printf '%s\n' "${pair#*=}" > "$d/${pair%%=*}"; done
    echo "$d"
}

file_mode() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }
versioned_dirs() { compgen -G "$BOXMUNGE_ROOT/.docs.*" | grep -cv '\.link$' || true; }

# --- install-docs ---------------------------------------------------------

new_root a
mkdir -p "$BOXMUNGE_ROOT/docs"
echo "old" > "$BOXMUNGE_ROOT/docs/OPERATIONS.md"
echo "gone" > "$BOXMUNGE_ROOT/docs/RETIRED.md"
src1="$(docs_src "OPERATIONS.md=v1 ops" "TRUST_MODEL.md=v1 trust")"
run_shim install-docs "$src1"
expect 0 "Installed docs" "install-docs replaces a plain docs directory"
[[ -L "$BOXMUNGE_ROOT/docs" ]] && pass "docs/ is now a swappable symlink" || fail "docs/ is not a symlink"
[[ "$(cat "$BOXMUNGE_ROOT/docs/OPERATIONS.md")" == "v1 ops" ]] && pass "doc content installed" \
    || fail "doc content not installed"
[[ ! -e "$BOXMUNGE_ROOT/docs/RETIRED.md" ]] && pass "doc missing from the release is removed" \
    || fail "stale doc survived"
[[ "$(file_mode "$BOXMUNGE_ROOT/docs/TRUST_MODEL.md")" == "644" ]] && pass "docs are 0644" \
    || fail "doc mode is $(file_mode "$BOXMUNGE_ROOT/docs/TRUST_MODEL.md")"

# A doc-only change (and a removed topic) reaches docs/ on the next install.
src2="$(docs_src "OPERATIONS.md=v2 ops" "IMAGES.md=v2 images")"
run_shim install-docs "$src2"
expect 0 "Installed docs" "a second install-docs succeeds"
[[ "$(cat "$BOXMUNGE_ROOT/docs/OPERATIONS.md")" == "v2 ops" ]] && pass "doc-only change reaches docs/" \
    || fail "doc-only change did not reach docs/"
[[ -f "$BOXMUNGE_ROOT/docs/IMAGES.md" ]] && pass "new topic file appears" || fail "new topic missing"
[[ ! -e "$BOXMUNGE_ROOT/docs/TRUST_MODEL.md" ]] && pass "removed topic disappears" \
    || fail "removed topic still present"
[[ "$(versioned_dirs)" -eq 1 ]] && pass "previous docs version cleaned up" \
    || fail "$(versioned_dirs) versioned docs dirs left behind"

# An empty source changes nothing.
empty="$(mktemp -d)"
run_shim install-docs "$empty"
expect 1 "no *.md docs" "install-docs refuses a source without docs"
[[ "$(cat "$BOXMUNGE_ROOT/docs/OPERATIONS.md")" == "v2 ops" ]] && pass "docs untouched after refusal" \
    || fail "docs changed after refusal"
rm -rf "$src1" "$src2" "$empty"
drop_root

# --- probation rollback restores the previous release's docs ---------------

new_root a  # active a = new release on probation; b = previous release
src_new="$(docs_src "OPERATIONS.md=new ops" "IMAGES.md=new images")"
run_shim install-docs "$src_new"
mkdir -p "$BOXMUNGE_ROOT/env-b/boxmunge-docs"
echo "previous ops" > "$BOXMUNGE_ROOT/env-b/boxmunge-docs/OPERATIONS.md"
mock_server a 'if [[ "$1" == "health" ]]; then exit 2; fi; exit 0'
rm "$BOXMUNGE_ROOT/env-b/bin/python"
printf '#!/usr/bin/env bash\nexit 0\n' > "$BOXMUNGE_ROOT/env-b/bin/python"
chmod +x "$BOXMUNGE_ROOT/env-b/bin/python"
write_probation "1.2.3" "b" "2999-01-01T00:00:00+00:00"
run_shim check-probation
expect 1 "Rollback complete" "a critical probation health check rolls back"
[[ "$(cat "$BOXMUNGE_ROOT/docs/OPERATIONS.md")" == "previous ops" ]] \
    && pass "rollback restored the previous release's docs" || fail "docs not rolled back"
[[ ! -e "$BOXMUNGE_ROOT/docs/IMAGES.md" ]] && pass "rollback removed the newer release's topic" \
    || fail "newer topic survived rollback"
rm -rf "$src_new"
drop_root

# --- install.sh delegates ---------------------------------------------------

grep -q 'bin/boxmunge-upgrade" install-docs "${SCRIPT_DIR}/on-server"' "$REPO_DIR/install.sh" \
    && pass "install.sh installs docs through install-docs" \
    || fail "install.sh does not use install-docs"

finish
