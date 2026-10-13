# SPDX-License-Identifier: Apache-2.0
"""Commands that drive the server over SSH: stage, prod-deploy, promote,
status, logs, mcp-serve."""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from typing import Any

from boxmunge_cli.config import ConfigError, discover_config, load_config


def _load_project_config() -> tuple[dict[str, Any], Path] | None:
    try:
        config_path = discover_config(Path.cwd())
        return load_config(config_path), config_path
    except ConfigError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return None


def _handshake(config: dict[str, Any], manifest_schema: int | None = None) -> bool:
    from boxmunge_cli.handshake import HandshakeError, check_server_compatibility
    try:
        check_server_compatibility(config, manifest_schema)
    except HandshakeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return False
    return True


def _connect() -> dict[str, Any] | None:
    """Load .boxmunge and confirm the server is compatible."""
    loaded = _load_project_config()
    if loaded is None or not _handshake(loaded[0]):
        return None
    return loaded[0]


def _manifest_schema(project_dir: Path) -> int:
    from boxmunge_cli.manifest import load_manifest
    schema = load_manifest(project_dir / "manifest.yml").get("schema_version", 1)
    assert isinstance(schema, int), "bundle validation guarantees an int schema_version"
    return schema


def _bundle_upload_and_run(command: str, server_flags: list[str]) -> int:
    from boxmunge_cli.bundle_cmd import run_bundle
    from boxmunge_cli.ssh import run_scp, run_ssh

    loaded = _load_project_config()
    if loaded is None:
        return 1
    config, config_path = loaded

    with tempfile.TemporaryDirectory() as tmpdir:
        exit_code = run_bundle(str(config_path.parent), output=tmpdir,
                               upload_hint=False)
        if exit_code != 0:
            return exit_code
        bundles = list(Path(tmpdir).glob("*.tar.gz"))
        if len(bundles) != 1:
            print("ERROR: Bundle was not created.", file=sys.stderr)
            return 1

        if not _handshake(config, _manifest_schema(config_path.parent)):
            return 1

        exit_code = run_scp(config, str(bundles[0]))
        if exit_code != 0:
            print("ERROR: Upload failed.", file=sys.stderr)
            return exit_code

    return run_ssh(config, command, config["project"], *server_flags)


def _cmd_stage(args: argparse.Namespace) -> int:
    return _bundle_upload_and_run("stage", ["--dry-run"] if args.dry_run else [])


def _cmd_prod_deploy(args: argparse.Namespace) -> int:
    flags = []
    if args.dry_run:
        flags.append("--dry-run")
    if args.no_snapshot:
        flags.append("--no-snapshot")
    return _bundle_upload_and_run("prod-deploy", flags)


def _cmd_promote(args: argparse.Namespace) -> int:
    from boxmunge_cli.ssh import run_ssh
    config = _connect()
    if config is None:
        return 1
    return run_ssh(config, "promote", config["project"],
                   *(["--dry-run"] if args.dry_run else []))


def _cmd_status(args: argparse.Namespace) -> int:
    from boxmunge_cli.ssh import run_ssh
    config = _connect()
    if config is None:
        return 1
    return run_ssh(config, "status", *(["--json"] if args.json else []))


def _cmd_logs(args: argparse.Namespace) -> int:
    from boxmunge_cli.ssh import run_ssh
    config = _connect()
    if config is None:
        return 1
    server_args = [config["project"]]
    if args.service:
        server_args.append(args.service)
    if args.tail is not None:
        server_args += ["--tail", str(args.tail)]
    if args.follow:
        server_args.append("--follow")
    return run_ssh(config, "logs", *server_args)


def _cmd_mcp_serve(args: argparse.Namespace) -> int:
    from boxmunge_cli.mcp_proxy import run_mcp_proxy
    config = _connect()
    if config is None:
        return 1
    return run_mcp_proxy(config)


def _positive_int(value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an integer: {value!r}")
    if n < 1:
        raise argparse.ArgumentTypeError(f"must be at least 1: {value!r}")
    return n


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "stage", help="Bundle, upload, and stage on the server",
        description="Bundle the project, upload it, and run 'stage <project>' "
                    "on the server. Verify the staging site, then 'promote'.")
    p.add_argument("--dry-run", action="store_true",
                   help="Upload and validate on the server without staging")
    p.set_defaults(func=_cmd_stage)

    p = subparsers.add_parser(
        "prod-deploy", help="Bundle, upload, and deploy straight to production",
        description="Bundle the project, upload it, and run "
                    "'prod-deploy <project>' on the server (skips staging).")
    p.add_argument("--dry-run", action="store_true",
                   help="Upload and validate on the server without deploying")
    p.add_argument("--no-snapshot", action="store_true",
                   help="Skip the pre-deploy backup snapshot")
    p.set_defaults(func=_cmd_prod_deploy)

    p = subparsers.add_parser("promote", help="Promote staging to production",
                              description="Run 'promote <project>' on the server.")
    p.add_argument("--dry-run", action="store_true",
                   help="Show what would be promoted without doing it")
    p.set_defaults(func=_cmd_promote)

    p = subparsers.add_parser("status", help="Show the server's project dashboard",
                              description="Run 'status' on the server (all projects).")
    p.add_argument("--json", action="store_true", help="Machine-readable output")
    p.set_defaults(func=_cmd_status)

    p = subparsers.add_parser("logs", help="Show this project's logs from the server",
                              description="Run 'logs <project>' on the server.")
    p.add_argument("service", nargs="?", help="Only this service's logs")
    p.add_argument("--tail", type=_positive_int, metavar="N",
                   help="Number of lines (server default 100)")
    p.add_argument("--follow", action="store_true", help="Stream new log lines")
    p.set_defaults(func=_cmd_logs)

    p = subparsers.add_parser(
        "mcp-serve", help="Run an MCP stdio proxy to the server",
        description="Pipe stdin/stdout to the server's 'mcp-serve' over SSH, "
                    "for use as an MCP server command in an agent host.")
    p.set_defaults(func=_cmd_mcp_serve)
