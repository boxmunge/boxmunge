"""boxmunge doctor — verify host health and configuration."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

from boxmunge.config import load_config, ConfigError
from boxmunge.paths import BoxPaths


def run_doctor(paths: BoxPaths, as_json: bool = False) -> int:
    """Run host health checks. Returns 0 if all pass, 1 if any fail."""
    results = []

    def check(name: str, passed: bool, detail: str = "") -> None:
        status = "PASS" if passed else "FAIL"
        results.append({"name": name, "status": status, "detail": detail})

    def warn(name: str, detail: str = "") -> None:
        results.append({"name": name, "status": "WARN", "detail": detail})

    # Directory structure
    for subdir in ["bin", "config", "caddy/sites", "projects", "state/health",
                   "state/deploy", "templates/project", "docs", "logs"]:
        path = paths.root / subdir
        check(f"Directory {subdir}", path.is_dir(), str(path))

    # Config file
    try:
        config = load_config(paths)
        check("Config file loads", True)
    except ConfigError as e:
        check("Config file loads", False, str(e))
        config = None

    # Backup key
    key_path = paths.backup_key
    if key_path.exists():
        check("Backup key exists", True)
    else:
        warn("Backup key exists", "Not found — run init-host or generate manually")

    # Pushover config
    if config:
        pushover = config.get("pushover", {})
        if pushover.get("user_key") and pushover.get("app_token"):
            check("Pushover configured", True)
        else:
            warn("Pushover configured", "Credentials empty — alerts won't work")

    # Backup remote
    if config:
        if config.get("backup_remote"):
            check("Backup remote configured", True)
        else:
            warn("Backup remote configured", "Not set — off-box sync won't work")

    # Docker
    docker_available = shutil.which("docker") is not None
    check("Docker available", docker_available)

    # age
    age_available = shutil.which("age") is not None
    check("age available", age_available,
          "" if age_available else "Install age for backup encryption")

    # rclone
    rclone_available = shutil.which("rclone") is not None
    if rclone_available:
        check("rclone available", True)
    else:
        warn("rclone available", "Not found — backup-sync won't work")

    # Caddy container
    if docker_available:
        try:
            result = subprocess.run(
                ["docker", "compose", "ps", "-q", "caddy"],
                cwd=paths.caddy, capture_output=True, text=True, check=False,
            )
            caddy_running = bool(result.stdout.strip())
            check("Caddy container running", caddy_running)
        except (FileNotFoundError, OSError):
            warn("Caddy container running", "Could not check")

    # Caddy config valid
    if docker_available:
        try:
            result = subprocess.run(
                ["docker", "compose", "exec", "caddy", "caddy", "validate",
                 "--config", "/etc/caddy/Caddyfile"],
                cwd=paths.caddy, capture_output=True, text=True, check=False,
            )
            check("Caddy config valid", result.returncode == 0,
                  result.stderr.strip() if result.returncode != 0 else "")
        except (FileNotFoundError, OSError):
            pass

    # Systemd timers (only on Linux)
    for timer_name in ["boxmunge-health", "boxmunge-backup", "boxmunge-backup-sync"]:
        try:
            result = subprocess.run(
                ["systemctl", "is-active", f"{timer_name}.timer"],
                capture_output=True, text=True, check=False,
            )
            is_active = result.stdout.strip() == "active"
            if is_active:
                check(f"Timer {timer_name}", True)
            else:
                warn(f"Timer {timer_name}", "Not active")
        except FileNotFoundError:
            pass  # Not on systemd — skip silently

    # Disk space
    try:
        usage = shutil.disk_usage(paths.root)
        free_gb = usage.free / (1024**3)
        if free_gb < 1.0:
            check("Disk space", False, f"{free_gb:.1f}GB free — critically low")
        elif free_gb < 5.0:
            warn("Disk space", f"{free_gb:.1f}GB free — getting low")
        else:
            check("Disk space", True, f"{free_gb:.1f}GB free")
    except OSError:
        pass

    # Report
    if as_json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            icon = {"PASS": "PASS", "FAIL": "FAIL", "WARN": "WARN"}[r["status"]]
            line = f"  {icon:<6} {r['name']}"
            if r["detail"]:
                line += f" — {r['detail']}"
            print(line)

    has_fail = any(r["status"] == "FAIL" for r in results)
    return 1 if has_fail else 0


def cmd_doctor(args: list[str]) -> None:
    """CLI entry point for doctor command."""
    paths = BoxPaths()
    as_json = "--json" in args
    print("boxmunge doctor")
    print("=" * 40)
    exit_code = run_doctor(paths, as_json=as_json)
    sys.exit(exit_code)
