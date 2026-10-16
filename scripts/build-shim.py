#!/usr/bin/env python3
"""Build the self-contained upgrade shim that releases ship.

In the source tree scripts/boxmunge-upgrade sources its functions from
scripts/boxmunge-upgrade.d/*.sh, which keeps each file a manageable size.
Every installer of the shim on a box, including the shims of older releases
that self-update during an upgrade, copies exactly one file:
scripts/boxmunge-upgrade. So the release build replaces the source loader
(the block between the two markers) with the libraries' contents, in the
order the loader names them.

Pure text transform: the same sources always give the same bytes.

Usage: build-shim.py <source-shim> <output>
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

BEGIN = "# >>> boxmunge-upgrade.d"
END = "# <<< boxmunge-upgrade.d"
LOADER_LIST = re.compile(r"^for lib in ([a-z ]+); do$", re.M)


def build(source: Path) -> str:
    text = source.read_text()
    start, end = text.find(BEGIN), text.find(END)
    if start < 0 or end < start or text.count(BEGIN) != 1 or text.count(END) != 1:
        raise SystemExit(f"{source}: expected exactly one {BEGIN!r} ... {END!r} loader block")
    loader = text[start:end]
    names = LOADER_LIST.findall(loader)
    if len(names) != 1:
        raise SystemExit(f"{source}: loader block must contain one `for lib in ...; do` line")
    lib_dir = source.parent / "boxmunge-upgrade.d"
    shipped = sorted(p.stem for p in lib_dir.glob("*.sh"))
    if sorted(names[0].split()) != shipped:
        raise SystemExit(f"{source}: loader lists {names[0].split()}, {lib_dir} has {shipped}")
    parts = []
    for name in names[0].split():
        body = (lib_dir / f"{name}.sh").read_text()
        body = body.removeprefix("# shellcheck shell=bash\n")
        parts.append(f"# >>> inlined from boxmunge-upgrade.d/{name}.sh by scripts/build-shim.py\n"
                     f"{body.rstrip()}\n"
                     f"# <<< boxmunge-upgrade.d/{name}.sh\n")
    after = text[end + len(END):].removeprefix("\n")
    return text[:start] + "\n".join(parts) + after


def main() -> int:
    if len(sys.argv) != 3:
        sys.stderr.write("usage: build-shim.py <source-shim> <output>\n")
        return 2
    out = Path(sys.argv[2])
    out.write_text(build(Path(sys.argv[1])))
    out.chmod(0o755)
    return 0


if __name__ == "__main__":
    sys.exit(main())
