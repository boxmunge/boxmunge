# SPDX-License-Identifier: Apache-2.0
"""Linux capability names: canonical spelling and the shared denylist.

One source of truth for both places a capability can be granted to a
container: a user compose.yml `cap_add`, and the manifest's
`security.cap_add`. Docker accepts any letter case and an optional `CAP_`
prefix (`cap_sys_admin`, `CAP_SYS_ADMIN`, `SYS_ADMIN` are the same
capability), so every comparison goes through `normalise_cap` first.
"""
from __future__ import annotations

# Every capability boxmunge recognises, in canonical spelling (upper case,
# no CAP_ prefix). Manifest cap_add / cap_drop entries must use this form.
VALID_CAP_NAMES: frozenset[str] = frozenset({
    "AUDIT_CONTROL", "AUDIT_READ", "AUDIT_WRITE",
    "BLOCK_SUSPEND", "BPF",
    "CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH",
    "FOWNER", "FSETID",
    "IPC_LOCK", "IPC_OWNER",
    "KILL", "LEASE", "LINUX_IMMUTABLE",
    "MAC_ADMIN", "MAC_OVERRIDE", "MKNOD",
    "NET_ADMIN", "NET_BIND_SERVICE", "NET_BROADCAST", "NET_RAW",
    "PERFMON",
    "SETFCAP", "SETGID", "SETPCAP", "SETUID",
    "SYS_ADMIN", "SYS_BOOT", "SYS_CHROOT", "SYS_MODULE",
    "SYS_NICE", "SYS_PACCT", "SYS_PTRACE", "SYS_RAWIO",
    "SYS_RESOURCE", "SYS_TIME", "SYS_TTY_CONFIG",
    "SYSLOG", "WAKE_ALARM",
})

# Capabilities with no legitimate opt-in under the default profile. Each
# one unwinds container isolation far enough to reach the host: mount and
# namespace control (SYS_ADMIN), reading any file (DAC_READ_SEARCH), kernel
# programs and tracing (BPF, PERFMON), kernel modules (SYS_MODULE), raw I/O
# and /dev/mem (SYS_RAWIO), kexec (SYS_BOOT), disabling AppArmor
# (MAC_ADMIN, MAC_OVERRIDE), and bypassing resource limits (SYS_RESOURCE).
# `ALL` grants every one of them.
#
# Capabilities that are dropped by default but have real uses (NET_RAW for
# ping, NET_ADMIN for VPN software, SYS_PTRACE for in-container debuggers)
# are NOT here: adding those back is the supported way to relax one
# protection. A service that genuinely needs a denied capability must use
# `security.profile: off` with a reason, which is loud on every deploy.
DENIED_CAPS: frozenset[str] = frozenset({
    "ALL",
    "SYS_ADMIN", "DAC_READ_SEARCH", "BPF", "PERFMON", "SYS_RESOURCE",
    "SYS_MODULE", "SYS_RAWIO", "SYS_BOOT", "MAC_ADMIN", "MAC_OVERRIDE",
})


def normalise_cap(raw: str) -> str:
    """Return the canonical spelling of a capability name.

    Strips surrounding whitespace, upper-cases, and removes one leading
    `CAP_` prefix, mirroring how Docker interprets the value.
    """
    name = raw.strip().upper()
    if name.startswith("CAP_"):
        name = name[len("CAP_"):]
    return name


def is_denied_cap(raw: str) -> bool:
    """True if `raw`, in any spelling Docker accepts, is a denied capability."""
    return normalise_cap(raw) in DENIED_CAPS
