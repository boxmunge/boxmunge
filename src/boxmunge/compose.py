"""Generate Docker Compose override files for boxmunge proxy networking."""

from typing import Any

import yaml


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
    """
    project = manifest["project"]
    prefix = alias_prefix or project
    services: dict[str, Any] = {}

    for svc_name, svc in manifest.get("services", {}).items():
        svc_override: dict[str, Any] = {}
        routes = svc.get("routes", [])

        # Network aliases only for routable services
        if routes:
            alias = f"{prefix}-{svc_name}"
            svc_override["networks"] = {
                "boxmunge-proxy": {
                    "aliases": [alias],
                },
            }

        # env_files for ALL services
        if env_file_list:
            svc_override["env_file"] = list(env_file_list)

        # Resource limits for services that declare them
        limits = svc.get("limits")
        if limits:
            svc_override["deploy"] = {
                "resources": {
                    "limits": dict(limits),
                },
            }

        # Mount smoke scripts into services that declare a smoke test
        if svc.get("smoke"):
            svc_override["volumes"] = ["./boxmunge-scripts:/boxmunge-scripts:ro"]

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
