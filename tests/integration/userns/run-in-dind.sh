#!/bin/sh
# Entry point of the userns-dind CI job, inside a privileged docker:<v>-dind
# container (`docker run --rm`, so the daemon's store, an anonymous volume,
# goes with it). The tests stop, reconfigure and restart dockerd themselves
# (there is no systemd here), so this script starts the prior-store daemon,
# installs the runner and hands over to pytest. pytest imports boxmunge from
# src/ (pyproject's pythonpath), so nothing is installed from the checkout.
# Arguments, when given, replace the test paths (a local run of one file).
set -eu
# Alpine packages are not version-pinned, as the integration job's apt
# packages are not: Alpine offers no practical hash pinning.
apk add -q python3 py3-pip bash age attr acl e2fsprogs-extra libcap-setcap shadow shadow-subids >/dev/null
cp -a /src /work
cd /work
python3 -m venv /venv
/venv/bin/pip install -q --disable-pip-version-check --require-hashes \
    -r requirements.txt -r tests/integration/userns/requirements-dind.txt
mkdir -p /etc/docker
case "${BOXMUNGE_DIND_PRIOR_STORE:?set by the CI matrix}" in
    containerd) echo '{}' > /etc/docker/daemon.json
        # The system containerd Docker's packages run as a service of its own,
        # for test_commit_system_containerd (dockerd here embeds one). Kept off
        # PATH, so dockerd keeps its embedded one for the other modules.
        case "$(uname -m)" in
            x86_64) arch=amd64 sum=02ad3a7e80d7d2c018c7134d5eca7e301283db6895f100b957fb52ad8e5a30fd ;;
            aarch64) arch=arm64 sum=d3aba9347650505df79858bb9cbf1be52080fd8145f72dd9308d4936f487fb74 ;;
            *) echo "no pinned containerd for $(uname -m)" >&2; exit 2 ;;
        esac
        tarball=/tmp/containerd-static.tar.gz
        wget -qO "$tarball" "https://github.com/containerd/containerd/releases/download/v2.4.1/containerd-static-2.4.1-linux-$arch.tar.gz"
        echo "$sum  $tarball" | sha256sum -c -s
        mkdir -p /opt/containerd-system
        tar -xzf "$tarball" -C /opt/containerd-system bin/containerd
        export BOXMUNGE_DIND_SYSTEM_CONTAINERD=/opt/containerd-system/bin/containerd ;;
    overlay2) echo '{"storage-driver": "overlay2", "features": {"containerd-snapshotter": false}}' > /etc/docker/daemon.json ;;
    *) echo "unknown prior store $BOXMUNGE_DIND_PRIOR_STORE" >&2; exit 2 ;;
esac
# An operator key the migration must keep, and a way past Docker Hub's pull
# rate limit on a shared address (BOXMUNGE_DIND_REGISTRY_MIRROR, e.g.
# https://mirror.gcr.io).
if [ -n "${BOXMUNGE_DIND_REGISTRY_MIRROR:-}" ]; then
    python3 -c 'import json, sys; p = "/etc/docker/daemon.json"; d = json.load(open(p))
d["registry-mirrors"] = [sys.argv[1]]; json.dump(d, open(p, "w"))' "$BOXMUNGE_DIND_REGISTRY_MIRROR"
fi
cp /etc/docker/daemon.json /etc/docker/daemon.json.prior
dind dockerd >> /var/log/dockerd.log 2>&1 &
i=0
until docker info >/dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -lt 60 ] || { tail -50 /var/log/dockerd.log; exit 1; }; sleep 1
done
export BOXMUNGE_REQUIRE_INTEGRATION=1 BOXMUNGE_USERNS_DIND=1
[ "$#" -gt 0 ] || set -- tests/integration/userns
status=0
/venv/bin/python -m pytest "$@" -m userns_dind -q -p no:cacheprovider || status=$?
if [ "$status" -ne 0 ]; then
    echo "--- last lines of /var/log/dockerd.log ---" >&2
    tail -80 /var/log/dockerd.log >&2
fi
exit "$status"
