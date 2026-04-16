#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# boxmunge OS hardening.
# Called by init-host.sh on fresh installs. Not intended to be run standalone.
set -euo pipefail

banner() {
    echo ""
    echo "========================================================"
    echo "  $*"
    echo "========================================================"
}

# ---------------------------------------------------------------------------
# Kernel parameters (sysctl)
# ---------------------------------------------------------------------------
banner "Hardening: Kernel parameters"

cat > /etc/sysctl.d/90-boxmunge.conf <<'EOF'
# --- Network ---
# Anti-spoofing: reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Disable ICMP redirects (we're not a router)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Ignore ICMP broadcasts (smurf attack mitigation)
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2

# Disable IPv6 router advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# TIME-WAIT assassination protection
net.ipv4.tcp_rfc1337 = 1

# --- Kernel ---
# Hide kernel pointers from non-root
kernel.kptr_restrict = 2

# Restrict dmesg to root
kernel.dmesg_restrict = 1

# Restrict perf_event
kernel.perf_event_paranoid = 3

# Restrict unprivileged BPF
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# SysRq: allow only sync + reboot (4+16+32+64=116)
kernel.sysrq = 116

# Full ASLR
kernel.randomize_va_space = 2

# Disable core dumps from SUID binaries
fs.suid_dumpable = 0

# Prevent loading a new kernel at runtime
kernel.kexec_load_disabled = 1

# Restrict ptrace to parent processes only
kernel.yama.ptrace_scope = 2

# --- Filesystem ---
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
EOF

sysctl --system > /dev/null

# ---------------------------------------------------------------------------
# Kernel module blocklist
# ---------------------------------------------------------------------------
banner "Hardening: Kernel module blocklist"

cat > /etc/modprobe.d/boxmunge-blocklist.conf <<'EOF'
# Uncommon filesystems
install cramfs /bin/false
install freevxfs /bin/false
install hfs /bin/false
install hfsplus /bin/false
install jffs2 /bin/false
install udf /bin/false

# Uncommon network protocols
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false

# Hardware not present on a VPS
install usb-storage /bin/false
install firewire-core /bin/false
install firewire-ohci /bin/false
install firewire-sbp2 /bin/false
install bluetooth /bin/false
install btusb /bin/false
install cfg80211 /bin/false
install mac80211 /bin/false
install thunderbolt /bin/false
EOF

# ---------------------------------------------------------------------------
# Miscellaneous
# ---------------------------------------------------------------------------
banner "Hardening: Miscellaneous"

# Login banners — remove OS/version info leakage
echo "Authorized access only. All activity is logged." > /etc/issue
echo "Authorized access only. All activity is logged." > /etc/issue.net
> /etc/motd

# Disable ctrl-alt-del reboot
systemctl mask ctrl-alt-del.target > /dev/null 2>&1

echo "OS hardening complete (some changes effective on next boot)."
