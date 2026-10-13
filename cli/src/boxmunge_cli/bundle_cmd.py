# SPDX-License-Identifier: Apache-2.0
"""boxmunge bundle [project-dir]: build a validated, ready-to-upload bundle."""
from __future__ import annotations
import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
import yaml
from boxmunge_cli.config import ConfigError, load_config
from boxmunge_cli.manifest import load_manifest, validate_manifest, ManifestError
from boxmunge_cli.bundle_filter import IGNORE_FILE, BundlePlan, plan_bundle, write_bundle
from boxmunge_cli.ignore_rules import IgnoreFileError
from boxmunge_cli.manifest_id import add_manifest_id, ManifestIdError


BUNDLE_EPILOG = """\
What ships: everything in the project directory except
  - never shipped: .git/ .hg/ .svn/, .env and .env.* (but .env.example ships),
    the client's .boxmunge config
  - left out by default: node_modules/ .venv/ venv/ __pycache__/ *.pyc tool
    caches, .DS_Store, earlier <project>-*.tar.gz bundles, top-level data/
    and backups/ (re-include with a '!pattern' line in .boxmungeignore)
  - anything matched by .boxmungeignore (gitignore syntax)
Bundling stops with an error for secrets.env, a top-level repo/, symlinks
that are absolute or leave the tree, and special files, unless
.boxmungeignore leaves them out.

The project directory must contain:

  manifest.yml     Project manifest (see below)
  compose.yml      Docker Compose file for the project's services

'boxmunge init' writes the project id (a ULID). If manifest.yml has none,
bundle adds a single 'id:' line and leaves the rest of the file untouched.

Manifest format (manifest.yml), abridged. Full reference: 'agent-help' on
the server (PROJECT_CONVENTIONS). bundle checks only the shape; the server
validates everything on stage/prod-deploy (--dry-run checks without deploying).

  schema_version: 3
  id: <ULID written by init>
  project: myapp                    # must match 'project' in .boxmunge
  source: bundle
  hosts:
    - myapp.example.com             # hostnames Caddy serves (lowercase)
  services:
    web:                            # a service name from compose.yml
      port: 8080                    # container port
      routes:
        - path: /
      health: /healthz              # optional
      smoke: boxmunge-scripts/smoke.sh
      limits:
        memory: 256m
        cpus: "0.5"
      writable:                     # read-only rootfs: paths the app writes
        ephemeral: [/var/cache/myapp]
  backup:
    type: none                      # none | postgres | mysql | files | custom
    # dump_command / restore_command are required unless type is none

Deploying (with .boxmunge from 'boxmunge init'):

  boxmunge stage          # bundle, upload, stage; then check the staging site
  boxmunge promote        # promote staging to production
  boxmunge prod-deploy    # or skip staging
"""

def _err(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)


def _resolve_bundle_path(project_dir: Path, project_name: str,
                         output: str | None) -> Path | None:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%S")
    filename = f"{project_name}-{timestamp}.tar.gz"
    if not output:
        return project_dir.parent / filename
    output_path = Path(output).resolve()
    if output_path.is_dir():
        return output_path / filename
    if not output_path.parent.is_dir():
        _err(f"Output directory does not exist: {output_path.parent}")
        return None
    return output_path


def _config_mismatch(project_dir: Path, project_name: str) -> str | None:
    """Error text if the project's .boxmunge names a different project."""
    config_path = project_dir / ".boxmunge"
    if not config_path.is_file():
        return None
    try:
        config = load_config(config_path)
    except ConfigError as e:
        return str(e)
    if config["project"] != project_name:
        return (f"{config_path} deploys project '{config['project']}' but manifest.yml "
                f"declares '{project_name}'. Make them agree before deploying: the "
                "server files the bundle under the manifest's name and runs the "
                ".boxmunge project.")
    return None


def _report_plan(plan: BundlePlan) -> None:
    for rel, reason in plan.excluded:
        print(f"  excluded: {rel}  ({reason})", file=sys.stderr)


def run_bundle(project_dir_str: str, output: str | None = None,
               validate_only: bool = False, list_only: bool = False,
               upload_hint: bool = True) -> int:
    project_dir = Path(project_dir_str).resolve()
    if not project_dir.is_dir():
        _err(f"Not a directory: {project_dir}")
        return 1

    manifest_path = project_dir / "manifest.yml"
    if not manifest_path.exists():
        _err(f"No manifest.yml in {project_dir}")
        return 1

    try:
        manifest = load_manifest(manifest_path)
    except ManifestError as e:
        _err(str(e))
        return 1

    project_name = manifest.get("project")
    errors, warnings = validate_manifest(manifest, require_id=validate_only)
    if errors:
        _err("Manifest validation failed:")
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 1
    mismatch = _config_mismatch(project_dir, project_name)
    if mismatch:
        _err(mismatch)
        return 1

    if not manifest.get("id") and not (validate_only or list_only):
        try:
            manifest["id"] = add_manifest_id(manifest_path)
        except ManifestIdError as e:
            _err(str(e))
            return 1
        print(f"  Added project id {manifest['id']} to manifest.yml. Commit this change:"
              " the id is the project's identity on the server.", file=sys.stderr)

    for w in warnings:
        print(f"  WARN: {w}", file=sys.stderr)

    compose_path = project_dir / "compose.yml"
    if not compose_path.exists():
        _err(f"No compose.yml in {project_dir}")
        return 1

    try:
        compose_data = yaml.safe_load(compose_path.read_text())
        if not isinstance(compose_data, dict):
            _err("compose.yml is not a valid YAML mapping")
            return 1
    except yaml.YAMLError as e:
        _err(f"compose.yml parse error: {e}")
        return 1

    if validate_only:
        print(f"Local checks passed for '{project_name}'. The server validates the full "
              "manifest on stage/prod-deploy; add --dry-run to check without deploying.")
        return 0

    bundle_path = _resolve_bundle_path(project_dir, project_name, output)
    if bundle_path is None:
        return 1

    try:
        plan = plan_bundle(project_dir, project_name, skip=bundle_path)
    except IgnoreFileError as e:
        _err(f"{IGNORE_FILE}: {e}")
        return 1
    _report_plan(plan)
    if plan.refused:
        _err("Refusing to bundle. Remove these paths, or list them in "
             f"{IGNORE_FILE} to leave them out:")
        for rel, reason in plan.refused:
            print(f"  {rel}: {reason}", file=sys.stderr)
        return 1

    if list_only:
        for rel in plan.shipped:
            print(rel)
        return 0

    write_bundle(plan, project_name, bundle_path)

    size_mb = bundle_path.stat().st_size / (1024 * 1024)
    print(f"Bundle created: {bundle_path}")
    print(f"  Size: {size_mb:.1f} MB")
    if upload_hint:
        _print_upload_hint(project_dir, project_name, bundle_path)
    return 0


def _print_upload_hint(project_dir: Path, project_name: str, bundle_path: Path) -> None:
    if (project_dir / ".boxmunge").is_file():
        print("  Deploy with: boxmunge stage (then boxmunge promote), or boxmunge prod-deploy")
        return
    print("  No .boxmunge here ('boxmunge init' creates one). To deploy by hand:")
    print(f"    scp -P 922 {bundle_path} deploy@<server>:")
    print(f"    ssh -p 922 deploy@<server> prod-deploy {project_name}")


def _cmd_bundle(args: argparse.Namespace) -> int:
    return run_bundle(args.project_dir, output=args.output,
                      validate_only=args.validate, list_only=args.list)


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "bundle", help="Build a deployable bundle",
        description="Validate the project and build <project>-<timestamp>.tar.gz.",
        epilog=BUNDLE_EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("project_dir", nargs="?", default=".",
                   help="Project directory (default: current directory)")
    p.add_argument("--output", metavar="PATH",
                   help="Directory or file to write (default: the project's parent dir)")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--validate", action="store_true",
                      help="Validate only; write nothing")
    mode.add_argument("--list", action="store_true",
                      help="Print what would ship (stdout) and what is left out (stderr)")
    p.set_defaults(func=_cmd_bundle)
