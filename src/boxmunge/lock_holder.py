"""Name the process holding an flock, from /proc/locks."""

import os
from pathlib import Path

CMDLINE_MAX = 200


def lock_holder(lock_path: Path, proc: Path = Path("/proc")) -> str | None:
    """Describe the holder of ``lock_path``: ``"pid N: <cmdline>"``.

    Matches the lock file's device and inode against /proc/locks. Returns
    ``"pid N"`` when the holder's cmdline cannot be read (it exited, or
    belongs to another user), and None when no holder is listed.
    """
    st = lock_path.stat()
    wanted = (os.major(st.st_dev), os.minor(st.st_dev), st.st_ino)
    for line in (proc / "locks").read_text().splitlines():
        fields = line.split()
        if len(fields) < 6:
            continue
        major, minor, inode = fields[5].split(":")
        if (int(major, 16), int(minor, 16), int(inode)) == wanted:
            return _describe(int(fields[4]), proc)
    return None


def _describe(pid: int, proc: Path) -> str:
    try:
        raw = (proc / str(pid) / "cmdline").read_bytes()
    except OSError:
        return f"pid {pid}"
    cmd = raw.replace(b"\0", b" ").decode(errors="replace").strip()
    return f"pid {pid}: {cmd[:CMDLINE_MAX]}" if cmd else f"pid {pid}"
