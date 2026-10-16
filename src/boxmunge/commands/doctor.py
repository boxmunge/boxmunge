"""boxmunge doctor — verify host health and configuration."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

from boxmunge.config import load_config, ConfigError
from boxmunge.docker_run import docker_env
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

    # SFTP subsystem wired to the boxmunge wrapper, which refuses SFTP for
    # deploy (uploads use `scp -O`). If sshd points elsewhere, in particular at
    # internal-sftp, which never passes through the restricted shell, deploy
    # gets unconfined filesystem access. install.sh keeps this in sync, but
    # config drift (manual edits, package upgrades, old bootstrap) can break
    # it silently, so we check it explicitly.
    sshd_config = Path("/etc/ssh/sshd_config")
    expected_sftp = "/opt/boxmunge/bin/boxmunge-sftp"
    if sshd_config.exists():
        try:
            actual = None
            for raw in sshd_config.read_text().splitlines():
                stripped = raw.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                parts = stripped.split()
                if len(parts) >= 3 and parts[0] == "Subsystem" and parts[1] == "sftp":
                    actual = parts[2]
                    break
            if actual is None:
                check("SFTP subsystem wired", False,
                      "no 'Subsystem sftp' line in sshd_config")
            elif actual == expected_sftp:
                check("SFTP subsystem wired", True, f"-> {actual}")
            else:
                check("SFTP subsystem wired", False,
                      f"sshd routes SFTP to {actual!r}, expected {expected_sftp!r} "
                      "— deploy may get unconfined SFTP")
        except OSError as e:
            warn("SFTP subsystem wired", f"could not read {sshd_config}: {e}")

    # MCP is part of every install; without it agents cannot operate the box.
    from boxmunge.commands.mcp_serve_cmd import MCP_REPAIR, mcp_import_error
    mcp_error = mcp_import_error()
    check("MCP package installed", mcp_error is None,
          "" if mcp_error is None else f"{mcp_error}. {MCP_REPAIR}")

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
    if docker_available:
        from boxmunge.compose_version import compose_version_problem
        problem = compose_version_problem()
        check("Docker Compose version supported", problem is None, problem or "")

    # age and rclone run only inside the system container (no host fallback)
    from boxmunge.system_container import connect, SystemContainerError
    try:
        connect(paths)
        check("System container (age, rclone)", True)
    except SystemContainerError as e:
        check("System container (age, rclone)", False, str(e))

    # Caddy container
    if docker_available:
        try:
            result = subprocess.run(
                ["docker", "compose", "ps", "-q", "caddy"],
                cwd=paths.caddy, capture_output=True, text=True, check=False,
                env=docker_env(),
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
                env=docker_env(),
            )
            check("Caddy config valid", result.returncode == 0,
                  result.stderr.strip() if result.returncode != 0 else "")
        except (FileNotFoundError, OSError):
            pass

    # Systemd timers (only on Linux)
    from boxmunge.health_checks.hardening import BOXMUNGE_TIMERS
    for timer in BOXMUNGE_TIMERS:
        timer_name = timer.removesuffix(".timer")
        try:
            result = subprocess.run(
                ["systemctl", "is-active", timer],
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

    # Pairs like `foo` / `foo-bar` registered before project-add refused them
    # can share container names (project_registry.name_collisions).
    from boxmunge.project_registry import load_registered_projects, overlapping_pairs
    pairs = overlapping_pairs(load_registered_projects(paths))
    if pairs:
        warn("Project names", "overlapping names can share container names: "
             + ", ".join(f"{a} / {b}" for a, b in pairs)
             + ". Avoid service names in the shorter project that start with the "
               "longer one's suffix (e.g. bar-* in foo next to foo-bar).")

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
    known_flags = {"--json"}
    unknown = [a for a in args if a not in known_flags]
    if unknown:
        print(
            f"ERROR: unknown argument(s): {' '.join(unknown)}",
            file=sys.stderr,
        )
        print("Usage: boxmunge doctor [--json]", file=sys.stderr)
        sys.exit(2)

    paths = BoxPaths()
    as_json = "--json" in args
    if not as_json:
        print("boxmunge doctor")
        print("=" * 40)
    exit_code = run_doctor(paths, as_json=as_json)
    sys.exit(exit_code)
