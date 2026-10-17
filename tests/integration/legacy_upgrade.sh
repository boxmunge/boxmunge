#!/usr/bin/env bash
# tests/integration/legacy_upgrade.sh <kind> <path> <project> — run as root in a
# throwaway container by test_legacy_upgrade.py, from an image holding
# boxmunge 0.10.1 (`git archive v0.10.1`) in /venv-0101 and this tree's built
# bundle in /venv-beta, with the host's /var/run/docker.sock mounted.
#
# boxmunge 0.10.1 deploys v1 of a busybox project and stages v2 the way it
# does (<kind>: bundle | bundle-recreated | leftover | git). The beta's
# `upgrade --dry-run` and `upgrade --apply` then run against it, and <path>
# continues:
#   rollback      the shim's rollback after a probation failure: 0.10.1's
#                 `stash restore --latest` and `upgrade --apply`, then its own
#                 `unstage` must work;
#   failed-apply  the same after the beta's apply failed (Caddy refused);
#   resolve       the beta's `legacy-stage`, then a normal deploy.
# Facts are printed as KEY=value lines for the test to assert, then the logs.
# The shared daemon runs no boxmunge Caddy, so a stand-in answers Caddy's
# validate and reload, and refuses them while /tmp/caddy-refuses exists (no
# environment variable reaches it: Docker runs with docker_env()).
set -uo pipefail
KIND="$1" WAY="$2" P="$3" R=/opt/boxmunge
LOG=/tmp/legacy.log
: > "$LOG"
old() { /venv-0101/bin/boxmunge-server "$@"; }
new() { /venv-beta/bin/boxmunge-server "$@"; }
# run <KEY> <cmd...>: run quietly, keep the output, print KEY_RC=<rc>.
run() {
    local key="$1" rc=0; shift
    "$@" > "/tmp/out.$key" 2>&1 || rc=$?
    { echo "### $key: $* (rc=$rc)"; cat "/tmp/out.$key"; } >> "$LOG"
    echo "${key}_RC=$rc"
}
fact() { echo "$1=$2"; }
cleanup() {
    for p in "$P" "$P-staging"; do
        docker ps -aq --filter "label=com.docker.compose.project=$p" | xargs -r docker rm -f >/dev/null
        docker network ls -q --filter "label=com.docker.compose.project=$p" | xargs -r docker network rm >/dev/null
    done
    echo "--- log"; cat "$LOG"
}
trap cleanup EXIT

# On the PATH Docker runs with (docker_run.DOCKER_ENV), ahead of /usr/bin.
cat > /usr/local/bin/docker <<'EOF'
#!/bin/sh
if [ "$1 $2 $3" = "compose exec caddy" ]; then [ -e /tmp/caddy-refuses ] && exit 1; exit 0; fi
exec /usr/bin/docker "$@"
EOF
chmod +x /usr/local/bin/docker

mkdir -p $R/{config,projects,state/deploy,state/health,caddy/sites,inbox,stashes,logs}
printf 'hostname: box.example.com\nadmin_email: ops@example.com\n' > $R/config/boxmunge.yml
echo 0.10.1 > $R/config/version

release() {  # release <dir> <version> <source> [declared]
    # `declared`: the services say who they run as, which the new release
    # requires of a registry image without USER and 0.10.1 does not know.
    local app='{internal: true}'
    [[ "${4:-}" == declared ]] && app='{internal: true, security: {user: image, reason: test}}'
    mkdir -p "$1"
    cat > "$1/manifest.yml" <<EOF
schema_version: 3
id: 01LEGACYTEST00000000000000
project: $P
source: $3
hosts: [$P.example.com]
services: {app: $app}
backup: {type: none}
EOF
    [[ "$3" == git ]] && printf 'repo: /tmp/origin.git\nref: main\n' >> "$1/manifest.yml"
    cat > "$1/compose.yml" <<EOF
services:
  app:
    image: busybox:1.36
    command: ["sh", "-c", "trap 'exit 0' TERM; while :; do sleep 1; done"]
    network_mode: none
    environment: {VERSION: $2}
EOF
}
bundle() {  # bundle <version> <hour> [declared]: an inbox bundle named as reception names it
    local d; d=$(mktemp -d)
    release "$d/$P" "$1" bundle "${3:-}"
    tar -C "$d" -czf "$R/inbox/$P-2026-10-16T${2}0000000000.tar.gz" "$P"
}
commit() {  # commit <version> [declared]: a commit of the release to the origin's main
    release /tmp/work "$1" git "${2:-}"
    git -C /tmp/work add -A
    git -C /tmp/work -c user.name=t -c user.email=t@example.com commit -qm "$1"
    git -C /tmp/work push -q origin HEAD:main
}
version() {  # the VERSION production's (or staging's) container runs
    docker ps -q --filter "label=com.docker.compose.project=$1" | head -1 \
        | xargs -r docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' \
        | sed -n 's/^VERSION=//p'
}

if [[ "$KIND" == git ]]; then
    git init -q --bare -b main /tmp/origin.git
    git init -q -b main /tmp/work && git -C /tmp/work remote add origin /tmp/origin.git
    commit v1
    run REGISTER old project-add "$P"
    run ADD old add-git-project "$P" /tmp/origin.git
    # The deploy shell runs add-git-project as deploy, so the clone is deploy's.
    # 0.10.1 runs here as root: safe.directory stands in for running it as deploy
    # (the beta runs git as deploy, without the system config).
    chown -R deploy: "$R/projects/$P/repo"
    git config --system --add safe.directory '*'
    run DEPLOY_V1 old prod-deploy "$P"
    commit v2
    # 0.10.1 checks the ref out in repo/ without pulling: name the fetched commit.
    run STAGE old stage "$P" --ref origin/main
else
    run ADD old project-add "$P"
    bundle v1 09; run DEPLOY_V1 old prod-deploy "$P" --ref 2026-10-16T09
    bundle v2 10; run STAGE old stage "$P" --ref 2026-10-16T10
fi
case "$KIND" in
    # 0.10.1's resume starts production from the project dir: the staged files.
    bundle-recreated) run PAUSE old pause "$P" --yes; run RECREATE old resume "$P" --yes ;;
    leftover) run PROMOTE old promote "$P"
              rm -f "$R/state/staging/$P.json"; touch "$R/projects/$P/compose.boxmunge-staging.yml" ;;
esac
fact PROD_VERSION_BEFORE "$(version "$P")"

# Every file of the project, links as links (D19), its deploy state, staging
# state and site files, and repo/'s HEAD.
snap() {
    { cd "$R/projects/$P" && find . \( -type f -o -type l \) ! -path './repo/.git/*' -print0 \
          | sort -z | while IFS= read -r -d '' f; do
              if [[ -L "$f" ]]; then echo "$f -> $(readlink "$f")"; else sha256sum "$f"; fi
          done
      cd "$R" && sha256sum "state/deploy/$P.json" "caddy/sites/$P.conf"
      for f in "state/staging/$P.json" "caddy/sites/$P-staging.conf"; do
          [[ -e "$f" ]] && sha256sum "$f"; done
      git -C "$R/projects/$P/repo" rev-parse HEAD 2>/dev/null; } | sha256sum | cut -c1-16
}
ids() {  # every container of the project and its stage: ID and StartedAt
    for p in "$P" "$P-staging"; do docker ps -aq --no-trunc --filter "label=com.docker.compose.project=$p"; done \
        | sort | xargs -r docker inspect --format '{{.Id}} {{.State.StartedAt}}' | sha256sum | cut -c1-16
}
fact BEFORE_FILES "$(snap)"; fact BEFORE_IDS "$(ids)"
fact CONTAINERS_BEFORE "$(for p in "$P" "$P-staging"; do
    docker ps -q --filter "label=com.docker.compose.project=$p"; done | wc -l)"

run STASH old stash create   # the stash 0.10.1's shim makes before the swap
latest() { find $R/stashes -name 'boxmunge-stash-*.tar.gz' | sort | tail -1; }
tar -tvzf "$(latest)" | grep -q '^l' && fact STASH_LINKS_BEFORE yes
cp "$(latest)" /tmp/unrewritten-stash.tar.gz

new upgrade --dry-run > /tmp/dry 2>&1; fact DRY_RC $?
cat /tmp/dry >> "$LOG"
grep -q "will be left as is" /tmp/dry && fact DRY_LEFT yes
[[ "$WAY" == failed-apply ]] && touch /tmp/caddy-refuses
run APPLY new upgrade --apply
rm -f /tmp/caddy-refuses
fact AFTER_FILES "$(snap)"; fact AFTER_IDS "$(ids)"
[[ "$KIND" != git ]] || { [[ -L $R/projects/$P/manifest.yml ]] && fact GIT_LINK yes; }
tar -tvzf "$(latest)" | grep -q '^l' || fact STASH_LINKS none
fact RECORD_KIND "$(python3 -c "import json,sys; print(json.load(open('$R/state/legacy-stages.json'))['$P']['kind'])" 2>/dev/null)"
run DEPLOY_REFUSED new prod-deploy "$P"
run PAUSE_REFUSED new pause "$P" --yes
for k in DEPLOY_REFUSED PAUSE_REFUSED; do
    grep -q "staged by boxmunge 0.10.1" "/tmp/out.$k" && fact "${k}_WHY" legacy-stage
done
fact IDS_AFTER_REFUSALS "$(ids)"

case "$WAY" in
rollback|failed-apply)
    # The control, from the state the real restore starts from: 0.10.1 cannot
    # restore the stash its shim made, unrewritten. It writes members in
    # order, so what it wrote before it stopped the real restore writes again.
    if [[ "$KIND" == git ]]; then
        control=$R/stashes/boxmunge-stash-2099-01-01T000000.tar.gz
        cp /tmp/unrewritten-stash.tar.gz "$control"
        run UNREWRITTEN_RESTORE old stash restore --latest
        # 0.10.1's data_filter refuses the git manifest.yml link (D19 kept it).
        grep -qF "refusing to extract member 'projects/$P/manifest.yml'" /tmp/out.UNREWRITTEN_RESTORE \
            && grep -qF "is a link to an absolute path" /tmp/out.UNREWRITTEN_RESTORE \
            && fact UNREWRITTEN_RESTORE_WHY link-member
        rm -f "$control"
    fi
    run RESTORE old stash restore --latest
    fact RESTORED_FILES "$(snap)"
    run REAPPLY old upgrade --apply
    fact PROD_VERSION_REAPPLIED "$(version "$P")"
    if [[ "$KIND" != leftover ]]; then
        run OLD_UNSTAGE old unstage "$P"
        fact STAGING_LEFT "$(docker ps -aq --filter "label=com.docker.compose.project=$P-staging" | wc -l)"
        fact PROD_VERSION_AFTER "$(version "$P")"
    fi
    ;;
resolve)
    case "$KIND" in
        bundle-recreated)
            run DISCARD_UNCONFIRMED new legacy-stage "$P" --discard
            grep -q -- "--discard --confirm-recreated" /tmp/out.DISCARD_UNCONFIRMED \
                && fact DISCARD_UNCONFIRMED_WHY confirm-recreated
            run RESOLVE new legacy-stage "$P" --keep-staged ;;
        *) run RESOLVE new legacy-stage "$P" --discard ;;
    esac
    run SHOW_AFTER new legacy-stage "$P"
    grep -q "has no release staged by boxmunge 0.10.1" /tmp/out.SHOW_AFTER && fact SHOW_AFTER_WHY none
    fact STAGING_LEFT "$(docker ps -aq --filter "label=com.docker.compose.project=$P-staging" | wc -l)"
    fact PROD_VERSION_AFTER "$(version "$P")"
    if [[ "$KIND" == bundle-recreated ]]; then
        run ROLLBACK new rollback "$P" --yes
        fact PROD_VERSION_ROLLED_BACK "$(version "$P")"
    fi
    if [[ "$KIND" == git ]]; then commit v3 declared; run DEPLOY_AFTER new prod-deploy "$P" --ref main
    else bundle v3 11 declared; run DEPLOY_AFTER new prod-deploy "$P" --ref 2026-10-16T11; fi
    fact PROD_VERSION_DEPLOYED "$(version "$P")" ;;
*) echo "usage: legacy_upgrade.sh <kind> <rollback|failed-apply|resolve> <project>" >&2; exit 2 ;;
esac
