"""Generate Docker Compose override files for boxmunge proxy networking."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from boxmunge.fileutil import atomic_write_text
from boxmunge.paths import BoxPaths
from boxmunge.security_overlay import (
    resolve_security,
    render_compose_security_fragment,
)
from boxmunge.security_warn import warn_off_services


class ComposeError(ValueError):
    """Raised when a compose document is structurally invalid for boxmunge use."""


def _build_env_file_list(env_files: dict[str, str] | None) -> list[str]:
    """Build ordered env_file list from an env_files dict."""
    if not env_files:
        return []
    result = []
    for key in ("host_secrets", "project_env", "project_secrets"):
        if key in env_files:
            result.append(env_files[key])
    return result


def _build_service_override(
    manifest: dict[str, Any],
    env_file_list: list[str],
    alias_prefix: str | None = None,
) -> dict[str, Any]:
    """Build per-service overrides for all services in the manifest.

    Routable services (with routes) get network aliases.
    All services get env_files and resource limits if applicable.
    Services with a smoke test get boxmunge-scripts mounted.
    All services get container hardening fragments unless they opt out.
    """
    project = manifest["project"]
    prefix = alias_prefix or project
    project_security = manifest.get("security")
    services: dict[str, Any] = {}

    manifest_services = manifest.get("services", {})
    if not isinstance(manifest_services, dict):
        raise ComposeError(
            f"manifest 'services' must be a mapping "
            f"(got {type(manifest_services).__name__})"
        )

    for svc_name, svc in manifest_services.items():
        svc_override: dict[str, Any] = {}
        routes = svc.get("routes", [])

        if routes:
            alias = f"{prefix}-{svc_name}"
            svc_override["networks"] = {
                "default": {},
                "boxmunge-proxy": {"aliases": [alias]},
            }

        if env_file_list:
            svc_override["env_file"] = list(env_file_list)

        limits = svc.get("limits")
        if limits:
            svc_override["deploy"] = {"resources": {"limits": dict(limits)}}

        if svc.get("smoke"):
            svc_override["volumes"] = ["./boxmunge-scripts:/boxmunge-scripts:ro"]

        # Security hardening — silent defaults injected here.
        resolved = resolve_security(project_security, svc.get("security"))
        sec_fragment = render_compose_security_fragment(resolved)

        # Avoid Docker Compose's "can't set distinct values on 'pids_limit'
        # and 'deploy.resources.limits.pids'" error: when manifest limits
        # already created a deploy.resources.limits block, nest pids_limit
        # under it as `pids` rather than emitting at the top level.
        if "deploy" in svc_override and "pids_limit" in sec_fragment:
            pids_value = sec_fragment.pop("pids_limit")
            svc_override["deploy"]["resources"]["limits"]["pids"] = pids_value

        svc_override.update(sec_fragment)

        if svc_override:
            services[svc_name] = svc_override

    return services


def generate_compose_override(
    manifest: dict[str, Any],
    env_files: dict[str, str] | None = None,
) -> str:
    """Generate compose.boxmunge.yml content.

    Adds boxmunge-proxy network aliases to routable services, env_file
    directives to all services, and resource limits where declared.
    """
    env_file_list = _build_env_file_list(env_files)
    services = _build_service_override(manifest, env_file_list)

    override: dict[str, Any] = {
        "networks": {
            "boxmunge-proxy": {"external": True},
        },
    }
    if services:
        override["services"] = services

    return yaml.dump(override, default_flow_style=False, sort_keys=False)


def prepare_compose_override(
    paths: BoxPaths,
    manifest: dict[str, Any],
    component: str = "deploy",
) -> None:
    """Generate compose.boxmunge.yml for a project.

    `component` labels the SECURITY OFF log entry so callers from upgrade /
    resume don't misattribute the warning as "deploy". Lives at module
    scope (boxmunge.compose) rather than commands/ so cross-command
    coordination doesn't require a `commands/`-to-`commands/` import
    (audit A-2).
    """
    project_name = manifest["project"]
    override_path = paths.project_compose_override(project_name)
    override_path.parent.mkdir(parents=True, exist_ok=True)

    # Build env_files based on which files exist
    env_files: dict[str, str] = {}
    if paths.host_secrets.exists():
        env_files["host_secrets"] = str(paths.host_secrets)
    project_env = paths.project_dir(project_name) / "project.env"
    if project_env.exists():
        env_files["project_env"] = "./project.env"
    project_secrets = paths.project_secrets(project_name)
    if project_secrets.exists():
        env_files["project_secrets"] = "./secrets.env"

    content = generate_compose_override(manifest, env_files=env_files or None)
    atomic_write_text(override_path, content)

    # Deploy-time warning for any service resolving to profile: off.
    # Repeated by design — see spec §"Deploy-time warning".
    warn_off_services(paths, manifest, component=component)


def is_bind_mount(volume_str: str) -> bool:
    """Check if a volume string is a bind mount (starts with . / or ~)."""
    host_part = volume_str.split(":")[0]
    return host_part.startswith((".", "/", "~"))


def _rewrite_bind_mount(volume_str: str) -> str:
    """Rewrite a bind-mount host path to add -staging suffix.

    ./data:/app/data       -> ./data-staging:/app/data
    ./data:/app/data:ro    -> ./data-staging:/app/data:ro
    /abs/path:/container   -> /abs/path-staging:/container
    """
    parts = volume_str.split(":")
    host_path = parts[0]
    parts[0] = host_path + "-staging"
    return ":".join(parts)


def generate_staging_compose_base(compose_path: str | Path) -> str:
    """Read compose.yml and return a copy with ports stripped and bind mounts rewritten.

    Staging runs alongside production with a different project name.
    Docker Compose list-merging means an override file cannot remove ports
    declared in the base, so we generate a staging-specific base instead.
    Bind-mount host paths get a -staging suffix to prevent data sharing.
    Named volumes are left unchanged — Docker Compose's project naming
    already isolates them.
    """
    raw = Path(compose_path).read_text()
    doc = yaml.safe_load(raw)
    if not isinstance(doc, dict):
        raise ComposeError(
            f"compose.yml must be a YAML mapping at the top level "
            f"(got {type(doc).__name__})"
        )
    services = doc.get("services")
    if services is not None and not isinstance(services, dict):
        raise ComposeError(
            f"compose.yml 'services' must be a mapping "
            f"(got {type(services).__name__})"
        )
    for svc in (services or {}).values():
        if not isinstance(svc, dict):
            # A non-dict service entry is malformed but we don't have to fail
            # the whole file — just skip the rewrite for this entry.
            continue
        svc.pop("ports", None)
        volumes = svc.get("volumes")
        if volumes:
            svc["volumes"] = [
                _rewrite_bind_mount(v) if is_bind_mount(v) else v
                for v in volumes
            ]
    return yaml.dump(doc, default_flow_style=False, sort_keys=False)


def generate_staging_compose_override(
    manifest: dict[str, Any],
    env_files: dict[str, str] | None = None,
) -> str:
    """Generate compose.boxmunge-staging.yml content.

    Like the standard override, but with '-staging' suffixed network aliases.
    Includes env_files and resource limits so staging matches production.
    """
    project = manifest["project"]
    env_file_list = _build_env_file_list(env_files)
    services = _build_service_override(
        manifest, env_file_list, alias_prefix=f"{project}-staging"
    )

    override: dict[str, Any] = {
        "networks": {
            "boxmunge-proxy": {"external": True},
        },
    }
    if services:
        override["services"] = services

    return yaml.dump(override, default_flow_style=False, sort_keys=False)
