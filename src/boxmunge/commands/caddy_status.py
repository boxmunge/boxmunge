"""boxmunge caddy-status — show Caddy sites and certificate info."""

import subprocess
import sys
from pathlib import Path

from boxmunge.paths import BoxPaths


def run_caddy_status(paths: BoxPaths) -> int:
    """Show Caddy container status, active sites, and cert info."""
    print("Caddy Status")
    print("=" * 40)

    try:
        result = subprocess.run(
            ["docker", "compose", "ps", "--format", "json"],
            cwd=paths.caddy, capture_output=True, text=True, check=True,
        )
        if "caddy" in result.stdout.lower():
            print("  Container: running")
        else:
            print("  Container: NOT RUNNING")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("  Container: UNKNOWN (docker not available)")

    print("\nActive sites:")
    sites_dir = paths.caddy_sites
    if sites_dir.exists():
        confs = sorted(sites_dir.glob("*.conf"))
        if confs:
            for conf in confs:
                project = conf.stem
                first_line = conf.read_text().split("\n")[0].strip()
                print(f"  {project}: {first_line}")
        else:
            print("  (none)")
    else:
        print("  (sites directory missing)")

    try:
        result = subprocess.run(
            ["docker", "compose", "exec", "caddy",
             "caddy", "list-modules", "--versions"],
            cwd=paths.caddy, capture_output=True, text=True, check=False,
        )
        if result.returncode == 0 and "tls" in result.stdout:
            print("\n  TLS module: active")
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    return 0


def cmd_caddy_status(args: list[str]) -> None:
    paths = BoxPaths()
    sys.exit(run_caddy_status(paths))
