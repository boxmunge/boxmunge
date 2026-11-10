# SPDX-License-Identifier: Apache-2.0
"""Commands that drive the server over SSH: stage, prod-deploy, promote,
status, logs, mcp-serve."""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from typing import Any

from boxmunge_cli.exitcodes import FAILURE, USAGE, CliExit
from boxmunge_cli.config import (
    ConfigError,
    discover_config,
    load_config,
    validate_connection,
)


def _load_project_config() -> tuple[dict[str, Any], Path]:
    try:
        config_path = discover_config(Path.cwd())
        return load_config(config_path), config_path
    except ConfigError as e:
        raise CliExit(FAILURE, str(e)) from e


def _handshake(config: dict[str, Any], manifest_schema: int | None = None,
               batch: bool = False, flags: list[str] | tuple[str, ...] = (),
               features: tuple[str, ...] = ()) -> None:
    """Refuse an incompatible server, and one too old for `flags` or
    `features` (before anything is uploaded or sent)."""
    from boxmunge_cli.handshake import (
        HandshakeError, check_server_compatibility, require_server_feature,
        require_server_flags,
    )
    try:
        info = check_server_compatibility(config, manifest_schema, batch=batch)
        require_server_flags(info, flags, config.get("project"))
        for feature in features:
            require_server_feature(info, feature)
    except HandshakeError as e:
        raise CliExit(e.exit_code, str(e)) from e


def connect(features: tuple[str, ...] = (),
            flags: list[str] | tuple[str, ...] = ()) -> dict[str, Any]:
    """Load .boxmunge and confirm the server is compatible, and new enough
    for `features` (handshake.FEATURE_SINCE) and `flags` (FLAG_SINCE);
    CliExit if not."""
    config, _ = _load_project_config()
    _handshake(config, flags=flags, features=features)
    return config


def _manifest_schema(project_dir: Path) -> int:
    from boxmunge_cli.manifest import load_manifest
    schema = load_manifest(project_dir / "manifest.yml").get("schema_version", 1)
    assert isinstance(schema, int), "bundle validation guarantees an int schema_version"
    return schema


def _bundle_upload_and_run(command: str, server_flags: list[str]) -> int:
    from boxmunge_cli.bundle_cmd import run_bundle
    from boxmunge_cli.ssh import run_scp, run_ssh

    config, config_path = _load_project_config()

    with tempfile.TemporaryDirectory() as tmpdir:
        exit_code = run_bundle(str(config_path.parent), output=tmpdir,
                               upload_hint=False)
        if exit_code != 0:
            return exit_code
        bundles = list(Path(tmpdir).glob("*.tar.gz"))
        if len(bundles) != 1:
            print("ERROR: Bundle was not created.", file=sys.stderr)
            return 1

        _handshake(config, _manifest_schema(config_path.parent), flags=server_flags)

        print(f"Uploading {bundles[0].name} to {config['user']}@{config['server']}:"
              f"{config['port']} ...", file=sys.stderr)
        exit_code = run_scp(config, str(bundles[0]))
        if exit_code != 0:
            print("ERROR: Upload failed.", file=sys.stderr)
            return exit_code

    return run_ssh(config, command, config["project"], *server_flags)


def _cmd_stage(args: argparse.Namespace) -> int:
    return _bundle_upload_and_run("stage", [*(["--dry-run"] if args.dry_run else []),
                                            *(["--no-pull"] if args.no_pull else [])])


_PROD_DEPLOY_FLAGS = (("dry_run", "--dry-run"), ("no_snapshot", "--no-snapshot"),
                      ("no_pull", "--no-pull"), ("accept_stale_kev", "--accept-stale-kev"))


def _cmd_prod_deploy(args: argparse.Namespace) -> int:
    flags = [flag for attr, flag in _PROD_DEPLOY_FLAGS if getattr(args, attr)]
    if args.abandon:
        if flags:
            raise CliExit(USAGE, "--abandon takes no other options.")
        return _deploy_without_upload(["--abandon"], [])
    if args.redeploy:
        return _deploy_without_upload(["--redeploy"], flags)
    if args.ref is not None:
        return _deploy_without_upload(["--ref", args.ref], flags)
    return _bundle_upload_and_run("prod-deploy", flags)


def _deploy_without_upload(mode: list[str], flags: list[str]) -> int:
    """prod-deploy of what the server already has (--abandon, --redeploy,
    --ref): nothing is bundled or uploaded."""
    from boxmunge_cli.ssh import run_ssh
    config = connect(flags=[mode[0], *flags])
    return run_ssh(config, "prod-deploy", config["project"], *mode, *flags)


def _cmd_promote(args: argparse.Namespace) -> int:
    from boxmunge_cli.ssh import run_ssh
    config, _ = _load_project_config()
    flags = [*(["--dry-run"] if args.dry_run else []), *(["--no-pull"] if args.no_pull else [])]
    _handshake(config, flags=flags)
    return run_ssh(config, "promote", config["project"], *flags)


def _cmd_status(args: argparse.Namespace) -> int:
    from boxmunge_cli.ssh import run_ssh
    config = connect()
    return run_ssh(config, "status", *(["--json"] if args.json else []))


def _cmd_logs(args: argparse.Namespace) -> int:
    from boxmunge_cli.ssh import run_ssh
    flags = [*(["--follow"] if args.follow else []), *(["--staging"] if args.staging else [])]
    config = connect(flags=flags)
    server_args = [config["project"]]
    if args.service:
        server_args.append(args.service)
    if args.tail is not None:
        server_args += ["--tail", str(args.tail)]
    return run_ssh(config, "logs", *server_args, *flags)


def _mcp_config(args: argparse.Namespace) -> dict[str, Any]:
    """Connection for mcp-serve: --server flags, --config PATH, or the nearest .boxmunge."""
    if not args.server and (args.port or args.user):
        raise CliExit(USAGE, "--port and --user need --server.")
    try:
        if args.server:
            config = {"server": args.server, "port": args.port or 922,
                      "user": args.user or "deploy"}
            validate_connection(config)
            return config
        path = Path(args.config) if args.config else discover_config(Path.cwd())
        return load_config(path)
    except ConfigError as e:
        raise CliExit(FAILURE, str(e)) from e


def _cmd_mcp_serve(args: argparse.Namespace) -> int:
    from boxmunge_cli.mcp_proxy import run_mcp_proxy
    config = _mcp_config(args)
    _handshake(config, batch=True)
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
    p.add_argument("--no-pull", action="store_true",
                   help="Build from the base images in the server's image store instead of "
                        "checking their registries for newer digests")
    p.set_defaults(func=_cmd_stage)

    _register_prod_deploy(subparsers)

    p = subparsers.add_parser("promote", help="Promote staging to production",
                              description="Run 'promote <project>' on the server.")
    p.add_argument("--dry-run", action="store_true",
                   help="Show what would be promoted without doing it")
    p.add_argument("--no-pull", action="store_true",
                   help="Build from the base images in the server's image store instead of "
                        "checking their registries for newer digests")
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
    p.add_argument("--staging", action="store_true",
                   help="Staging's logs instead of production's (boxmunge-server 0.11.4 "
                        "or newer)")
    p.set_defaults(func=_cmd_logs)

    p = subparsers.add_parser(
        "mcp-serve", help="Run an MCP stdio proxy to the server",
        description="Pipe stdin/stdout to the server's 'mcp-serve' over SSH, "
                    "for use as an MCP server command in an agent host. The server's "
                    "MCP is server-wide, so no project is needed: pass --server (or "
                    "--config) because hosts usually start it outside the project.")
    where = p.add_mutually_exclusive_group()
    where.add_argument("--server", metavar="HOST",
                       help="Server to connect to (instead of a .boxmunge file)")
    where.add_argument("--config", metavar="PATH",
                       help="A .boxmunge file to read (default: the nearest one)")
    p.add_argument("--port", type=_positive_int, help="SSH port with --server (default 922)")
    p.add_argument("--user", help="SSH user with --server (default deploy)")
    p.set_defaults(func=_cmd_mcp_serve)


def _register_prod_deploy(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "prod-deploy", help="Bundle, upload, and deploy straight to production",
        description="Bundle the project, upload it, and run "
                    "'prod-deploy <project>' on the server (skips staging). "
                    "--redeploy, --ref and --abandon upload nothing: they act on "
                    "what the server already has.")
    p.add_argument("--dry-run", action="store_true",
                   help="Validate on the server without deploying (the bundle is still "
                        "uploaded, unless --redeploy or --ref)")
    p.add_argument("--no-snapshot", action="store_true",
                   help="Skip the pre-deploy backup snapshot")
    p.add_argument("--no-pull", action="store_true",
                   help="Build from the base images in the server's image store instead of "
                        "checking their registries for newer digests")
    p.add_argument("--accept-stale-kev", action="store_true",
                   help="Let a CVE-quarantined project's fix through although the server "
                        "has no usable CISA KEV catalog; logged and alerted. Never "
                        "overrides a catalog that lists a CVE still in the release's "
                        "images (boxmunge-server 0.11.5 or newer)")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--redeploy", action="store_true",
                      help="Deploy the release already installed again, as strictly "
                           "checked as a new deploy; uploads nothing (boxmunge-server "
                           "0.11.4 or newer)")
    mode.add_argument("--ref", metavar="REF",
                      help="Deploy REF, a bundle already in the server's inbox or a git "
                           "project's commit, or finish the open install of REF; "
                           "uploads nothing")
    mode.add_argument("--abandon", action="store_true",
                      help="Undo an interrupted install whose pre-deploy hook has not "
                           "run: the previous release's files go back (a first "
                           "deploy's code is removed); containers and data were never "
                           "touched. Uploads nothing; rerun it if it is interrupted")
    p.set_defaults(func=_cmd_prod_deploy)
