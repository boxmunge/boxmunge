#!/usr/bin/env bash
# tests/integration/sshd_hardening_probe.sh — run as root in a throwaway Debian 13
# container by test_sshd_hardening.py, with bootstrap/ at /bootstrap
# and src/ at /src.
#
# Builds a box the way init-host.sh does (deploy with the real restricted
# shell as its login shell and in the docker group, supervisor with bash,
# sshd.sh) on a cloud image whose 50-cloud-init.conf turns passwords on, then
# tries every SSH channel that could bypass the shell, as deploy, under three
# sshd configurations. Prints one line per attempt:
#   RESULT <phase> <user> <channel> <allowed|refused>
# plus the effective sshd settings for deploy and supervisor in each phase.
# shellcheck disable=SC2016  # stub bodies and BASH_ENV are literal on purpose
set -uo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq openssh-server openssh-client python3 python3-yaml >/dev/null || exit 1
set -e

printf '#!/bin/sh\nexit 0\n' > /usr/local/bin/systemctl
chmod +x /usr/local/bin/systemctl
# The shell hands allowed commands to boxmunge-server. The stand-in is bash,
# like the real wrapper, so a BASH_ENV that reached it would run.
printf '#!/usr/bin/env bash\necho "boxmunge-server ran: $* BASH_ENV=${BASH_ENV-unset}"\n' \
    > /usr/local/bin/boxmunge-server
chmod +x /usr/local/bin/boxmunge-server
ssh-keygen -A >/dev/null
mkdir -p /run/sshd /opt/boxmunge/bin /opt/boxmunge/env-active/bin /root/.ssh

# The venv as install.sh leaves it, with the package from /src: its python
# and the boxmunge-shell entry point. The login shell is install.sh's own
# wrapper (WRAPPER_NOW); WRAPPER_BEFORE is the one earlier releases wrote.
ln -s /usr/bin/python3 /opt/boxmunge/env-active/bin/python
cat > /opt/boxmunge/env-active/bin/boxmunge-shell <<'ENTRY'
#!/opt/boxmunge/env-active/bin/python
import sys
sys.path.insert(0, "/src")
from boxmunge.shell import main
sys.exit(main())
ENTRY
chmod 755 /opt/boxmunge/env-active/bin/boxmunge-shell
WRAPPER_NOW="$(sed -n "/^cat > \"\${BOXMUNGE_ROOT}\/bin\/boxmunge-shell\" <<'WRAPPER'$/,/^WRAPPER$/p" \
    /install.sh | sed '1d;$d')"
[[ "${WRAPPER_NOW}" == "#!/bin/sh"* ]] || { echo "WRAPPER_NOT_FOUND"; exit 1; }
WRAPPER_BEFORE='#!/usr/bin/env bash
exec /opt/boxmunge/env-active/bin/boxmunge-shell "$@"'
wrapper() { printf '%s\n' "$1" > /opt/boxmunge/bin/boxmunge-shell; chmod 755 /opt/boxmunge/bin/boxmunge-shell; }
wrapper "${WRAPPER_NOW}"
groupadd -f docker
useradd -m -s /opt/boxmunge/bin/boxmunge-shell deploy
useradd -m -s /bin/bash supervisor
usermod -aG docker deploy
install -d -o deploy -g deploy /opt/boxmunge/inbox /opt/boxmunge/inbox/.tmp
ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/id_ed25519
for user in deploy supervisor; do
    home="$(getent passwd "${user}" | cut -d: -f6)"
    install -d -m 700 -o "${user}" -g "${user}" "${home}/.ssh"
    install -m 600 -o "${user}" -g "${user}" /root/.ssh/id_ed25519.pub "${home}/.ssh/authorized_keys"
done

export SSH_PORT=922 DEPLOY_USER=deploy
# shellcheck source=/dev/null  # mounted into the container
. /bootstrap/sshd.sh
DROPIN=/etc/ssh/sshd_config.d/00-boxmunge.conf
echo "PasswordAuthentication yes" > /etc/ssh/sshd_config.d/50-cloud-init.conf

# What a forward would reach: a stand-in for /var/run/docker.sock
# (root:docker 0660) and a local TCP service. Both answer PONG.
python3 - <<'PY' &
import grp, os, socket, threading
def serve(s):
    s.listen()
    while True:
        c, _ = s.accept(); c.sendall(b"PONG\n"); c.close()
u = socket.socket(socket.AF_UNIX); u.bind("/run/docker.sock")
os.chown("/run/docker.sock", 0, grp.getgrnam("docker").gr_gid); os.chmod("/run/docker.sock", 0o660)
t = socket.socket(); t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); t.bind(("127.0.0.1", 7777))
threading.Thread(target=serve, args=(t,), daemon=True).start()
serve(u)
PY
set +e

SSH=(ssh -p 922 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
     -o LogLevel=ERROR -o ExitOnForwardFailure=yes)

# Prints PONG if something answers at the address (unix path or tcp port).
pong() {
    python3 - "$1" <<'PY' 2>/dev/null
import socket, sys, time
target = sys.argv[1]
for _ in range(30):
    try:
        if target.startswith("/"):
            s = socket.socket(socket.AF_UNIX); s.connect(target)
        else:
            s = socket.create_connection(("127.0.0.1", int(target)), timeout=2)
        s.settimeout(2)
        data = s.recv(16)
        if data:
            print(data.decode().strip()); sys.exit(0)
    except OSError:
        pass
    time.sleep(0.2)
PY
}

report() { echo "RESULT ${PHASE} $1 $2 $3"; }

# forward <user> <channel> <ssh forward option> <address to probe>
forward() {
    local user="$1" channel="$2" opt="$3" addr="$4" pid verdict=refused
    rm -f /tmp/fwd.sock /tmp/rfwd.sock
    "${SSH[@]}" -N "${opt}" "${user}@127.0.0.1" 2>/dev/null & pid=$!
    [[ "$(pong "${addr}")" == PONG ]] && verdict=allowed
    kill "${pid}" 2>/dev/null; wait "${pid}" 2>/dev/null
    report "${user}" "${channel}" "${verdict}"
}

probe_deploy() {
    forward deploy docker-sock-L "-L/tmp/fwd.sock:/run/docker.sock" /tmp/fwd.sock
    forward deploy tcp-L "-L7701:127.0.0.1:7777" 7701
    forward deploy tcp-R "-R7702:127.0.0.1:7777" 7702
    forward deploy streamlocal-R "-R/tmp/rfwd.sock:127.0.0.1:7777" /tmp/rfwd.sock
    local out verdict=refused
    out="$(timeout 10 "${SSH[@]}" -W 127.0.0.1:7777 deploy@127.0.0.1 </dev/null 2>/dev/null)"
    [[ "${out}" == PONG ]] && verdict=allowed
    report deploy stdio-W "${verdict}"
    # A forwarded agent appears as a deploy-owned socket while the session runs.
    eval "$(ssh-agent -s)" >/dev/null; ssh-add -q /root/.ssh/id_ed25519
    sleep 3 | "${SSH[@]}" -A deploy@127.0.0.1 >/dev/null 2>&1 & pid=$!
    verdict=refused
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        sleep 0.2
        [[ -n "$(find /tmp -path '/tmp/ssh-*' -name 'agent.*' -user deploy 2>/dev/null)" ]] \
            && { verdict=allowed; break; }
    done
    wait "${pid}"; ssh-agent -k >/dev/null
    report deploy agent "${verdict}"
    settings deploy
    settings supervisor
}

# Settings that show logins, forwarding and the Match block's scope (port and
# maxauthtries come from the main file, which sshd reads after the drop-ins).
settings() {
    echo "SETTINGS ${PHASE} $1 $(sshd -T -C "user=$1,host=localhost,addr=127.0.0.1" \
        | grep -E '^(passwordauthentication|kbdinteractiveauthentication|permitrootlogin|disableforwarding|allowtcpforwarding|allowstreamlocalforwarding|allowagentforwarding|x11forwarding|permittunnel|gatewayports|permituserrc|permittty|permituserenvironment|acceptenv|port|maxauthtries) ' \
        | sort | tr '\n' ',')"
}

restart_sshd() {
    [[ -f /run/sshd.pid ]] && kill "$(cat /run/sshd.pid)" && sleep 0.5
    sshd -t || { echo "SSHD_INVALID ${PHASE}"; exit 1; }
    /usr/sbin/sshd
    for _ in $(seq 50); do
        "${SSH[@]}" supervisor@127.0.0.1 true 2>/dev/null && return 0
        sleep 0.1
    done
    echo "SSHD_DOWN ${PHASE}"; exit 1
}

# 1. A box bootstrapped before the drop-in: Debian's main-file defaults for
#    forwarding, and cloud-init's drop-in turning passwords back on.
PHASE=fleet-before; rm -f "${DROPIN}"; restart_sshd; probe_deploy
forward supervisor tcp-L "-L7703:127.0.0.1:7777" 7703
# 2. That box once install.sh has run the hardening.
PHASE=fleet-after; bash /bootstrap/sshd-hardening.sh >/dev/null || exit 1
restart_sshd; probe_deploy
forward supervisor tcp-L "-L7703:127.0.0.1:7777" 7703
# 3. An operator opens TCP forwarding for supervisor in its own Match block:
#    the next install accepts it, and deploy stays closed.
PHASE=relaxed-after
printf 'Match User supervisor\n    AllowTcpForwarding yes\n' > /etc/ssh/sshd_config.d/10-ops.conf
bash /bootstrap/sshd-hardening.sh >/dev/null || exit 1
restart_sshd; probe_deploy
forward supervisor tcp-L "-L7703:127.0.0.1:7777" 7703

# A client variable that runs code: bash expands BASH_ENV before it runs a
# script, so this needs no file on the box. Prints whether it ran and what
# boxmunge-server saw.
inject() {
    rm -f /tmp/pwned
    local out
    out="$(BASH_ENV='$(touch /tmp/pwned)' "${SSH[@]}" -o SendEnv=BASH_ENV deploy@127.0.0.1 status 2>&1)"
    local verdict=refused
    [[ -e /tmp/pwned ]] && verdict=allowed
    report deploy bash-env "${verdict}"
    echo "SERVER ${PHASE} ${out}"
}
# 4. Before: the wrapper earlier releases wrote, and an operator's drop-in
#    accepting BASH_ENV from clients.
PHASE=env-before; rm -f "${DROPIN}"; wrapper "${WRAPPER_BEFORE}"
printf 'AcceptEnv BASH_ENV\n' > /etc/ssh/sshd_config.d/20-env.conf
restart_sshd; inject
# 5. The drop-in pins deploy's AcceptEnv, so sshd no longer passes it.
PHASE=env-after-sshd; bash /bootstrap/sshd-hardening.sh >/dev/null || exit 1
restart_sshd; inject
# 6. A Match block added after install widens it again (AcceptEnv adds up):
#    the wrapper and the shell still keep it from running anything.
PHASE=env-after-wrapper; wrapper "${WRAPPER_NOW}"
printf 'Match User deploy\n    AcceptEnv BASH_ENV\n' > /etc/ssh/sshd_config.d/30-widen.conf
restart_sshd; inject
rm /etc/ssh/sshd_config.d/20-env.conf /etc/ssh/sshd_config.d/30-widen.conf; restart_sshd

# The session itself still works: allowlisted commands and scp uploads.
echo "COMMAND $("${SSH[@]}" deploy@127.0.0.1 status --json 2>&1)"
echo "TTY $(echo exit | "${SSH[@]}" -tt deploy@127.0.0.1 2>&1 | tr -d '\r' | grep -c 'boxmunge>')"
echo "REFUSED $("${SSH[@]}" deploy@127.0.0.1 cat /etc/passwd 2>&1)"
mkdir -p /tmp/bundle/demo && echo 'project: demo' > /tmp/bundle/demo/manifest.yml
tar -czf /tmp/demo.tar.gz -C /tmp/bundle demo
echo "SCP $(scp -O -P 922 -o BatchMode=yes -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR /tmp/demo.tar.gz deploy@127.0.0.1: 2>&1)"
echo "INBOX $(ls /opt/boxmunge/inbox)"
