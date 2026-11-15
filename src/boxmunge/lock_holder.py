"""Name the process holding an flock, from /proc/locks."""

import os
import re
from pathlib import Path

CMDLINE_MAX = 200
# A held lock. A blocked waiter is listed as "N: -> FLOCK ...", which this
# does not match, so a waiter is never named as the holder.
_HELD = re.compile(r"^\d+: (?:FLOCK|POSIX|OFDLCK) +\S+ +\S+ +(\d+) +([0-9a-f]+):([0-9a-f]+):(\d+) ")


def lock_holder(lock_path: Path, proc: Path = Path("/proc")) -> str | None:
    """Describe the holder of ``lock_path``: ``"pid N: <cmdline>"``.

    Matches the lock file's device and inode against /proc/locks. Returns
    ``"pid N"`` when the holder's cmdline cannot be read (it exited, or
    belongs to another user), and None when no holder is listed.
    """
    st = lock_path.stat()
    wanted = (os.major(st.st_dev), os.minor(st.st_dev), st.st_ino)
    for line in (proc / "locks").read_text().splitlines():
        m = _HELD.match(line)
        if m and (int(m[2], 16), int(m[3], 16), int(m[4])) == wanted:
            pid = int(m[1])
            # pid 0: the holder is in a pid namespace we cannot see.
            return _describe(pid, proc) if pid else None
    return None


def _describe(pid: int, proc: Path) -> str:
    try:
        raw = (proc / str(pid) / "cmdline").read_bytes()
    except OSError:
        return f"pid {pid}"
    cmd = raw.replace(b"\0", b" ").decode(errors="replace").strip()
    return f"pid {pid}: {cmd[:CMDLINE_MAX]}" if cmd else f"pid {pid}"
