# SPDX-License-Identifier: Apache-2.0
"""boxmunge local CLI — command dispatch and help."""

import sys
from typing import Callable

from boxmunge_cli.init_cmd import cmd_init
from boxmunge_cli.bundle_cmd import cmd_bundle

HELP_TEXT = """\
boxmunge — deploy to your VPS in one command

Usage: boxmunge <command> [options]

Commands:
  init --server <host>    Create .boxmunge config, scaffold project
  bundle <dir>            Build a deployable bundle
  stage                   Bundle, upload, and stage on server
  promote                 Promote staging to production
  prod-deploy             Bundle, upload, and deploy to production
  status                  Show project status on server
  logs                    Show project logs from server
  mcp-serve               Start MCP proxy to server

Options:
  --version               Show version
  --help                  Show this help
"""


def _cmd_stage(args: list[str]) -> None:
    from boxmunge_cli.config import discover_config, load_config, ConfigError
    from boxmunge_cli.handshake import check_server_compatibility, HandshakeError
    from boxmunge_cli.bundle_cmd import run_bundle
    from boxmunge_cli.ssh import run_scp, run_ssh
    import tempfile
    from pathlib import Path

    try:
        config_path = discover_config(Path.cwd())
        config = load_config(config_path)
    except ConfigError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    project_dir = str(config_path.parent)
    with tempfile.TemporaryDirectory() as tmpdir:
        exit_code = run_bundle(project_dir, output=tmpdir)
        if exit_code != 0:
            sys.exit(exit_code)

        bundles = list(Path(tmpdir).glob("*.tar.gz"))
        if not bundles:
            print("ERROR: Bundle was not created.", file=sys.stderr)
            sys.exit(1)
        bundle_path = str(bundles[0])

        try:
            check_server_compatibility(config)
        except HandshakeError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)

        exit_code = run_scp(config, bundle_path)
        if exit_code != 0:
            print("ERROR: Upload failed.", file=sys.stderr)
            sys.exit(exit_code)

    sys.exit(run_ssh(config, "stage", config["project"]))


def _cmd_promote(args: list[str]) -> None:
    from boxmunge_cli.config import discover_config, load_config, ConfigError
    from boxmunge_cli.ssh import run_ssh
    from pathlib import Path

    try:
        config_path = discover_config(Path.cwd())
        config = load_config(config_path)
    except ConfigError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    sys.exit(run_ssh(config, "promote", config["project"]))


def _cmd_prod_deploy(args: list[str]) -> None:
    from boxmunge_cli.config import discover_config, load_config, ConfigError
    from boxmunge_cli.handshake import check_server_compatibility, HandshakeError
    from boxmunge_cli.bundle_cmd import run_bundle
    from boxmunge_cli.ssh import run_scp, run_ssh
    import tempfile
    from pathlib import Path

    try:
        config_path = discover_config(Path.cwd())
        config = load_config(config_path)
    except ConfigError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    project_dir = str(config_path.parent)
    with tempfile.TemporaryDirectory() as tmpdir:
        exit_code = run_bundle(project_dir, output=tmpdir)
        if exit_code != 0:
            sys.exit(exit_code)

        bundles = list(Path(tmpdir).glob("*.tar.gz"))
        if not bundles:
            print("ERROR: Bundle was not created.", file=sys.stderr)
            sys.exit(1)
        bundle_path = str(bundles[0])

        try:
            check_server_compatibility(config)
        except HandshakeError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)

        exit_code = run_scp(config, bundle_path)
        if exit_code != 0:
            print("ERROR: Upload failed.", file=sys.stderr)
            sys.exit(exit_code)

    sys.exit(run_ssh(config, "prod-deploy", config["project"]))


def _cmd_ssh_passthrough(command: str) -> Callable[[list[str]], None]:
    def handler(args: list[str]) -> None:
        from boxmunge_cli.config import discover_config, load_config, ConfigError
        from boxmunge_cli.ssh import run_ssh
        from pathlib import Path

        try:
            config_path = discover_config(Path.cwd())
            config = load_config(config_path)
        except ConfigError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)

        sys.exit(run_ssh(config, command, config["project"], *args))
    return handler


def _cmd_mcp_serve(args: list[str]) -> None:
    from boxmunge_cli.mcp_proxy import run_mcp_proxy
    from boxmunge_cli.config import discover_config, load_config, ConfigError
    from pathlib import Path

    try:
        config_path = discover_config(Path.cwd())
        config = load_config(config_path)
    except ConfigError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    sys.exit(run_mcp_proxy(config))


COMMANDS: dict[str, Callable[[list[str]], None]] = {
    "init": cmd_init,
    "bundle": cmd_bundle,
    "stage": _cmd_stage,
    "promote": _cmd_promote,
    "prod-deploy": _cmd_prod_deploy,
    "status": _cmd_ssh_passthrough("status"),
    "logs": _cmd_ssh_passthrough("logs"),
    "mcp-serve": _cmd_mcp_serve,
}


def main() -> None:
    args = sys.argv[1:]

    if not args or args[0] in ("--help", "-h"):
        print(HELP_TEXT)
        sys.exit(0)

    if args[0] in ("--version", "-V"):
        from boxmunge_cli import __version__
        print(f"boxmunge {__version__}")
        sys.exit(0)

    command = args[0]
    command_args = args[1:]

    handler = COMMANDS.get(command)
    if handler is None:
        print(f"boxmunge: unknown command '{command}'", file=sys.stderr)
        print("Run 'boxmunge --help' for usage.", file=sys.stderr)
        sys.exit(2)

    handler(command_args)
