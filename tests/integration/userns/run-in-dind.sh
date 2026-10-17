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
    containerd) echo '{}' > /etc/docker/daemon.json ;;
    overlay2) echo '{"storage-driver": "overlay2", "features": {"containerd-snapshotter": false}}' > /etc/docker/daemon.json ;;
    *) echo "unknown prior store $BOXMUNGE_DIND_PRIOR_STORE" >&2; exit 2 ;;
esac
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
