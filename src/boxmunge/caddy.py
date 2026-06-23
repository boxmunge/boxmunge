"""Generate Caddy site configuration from a project manifest."""

from typing import Any

from boxmunge.fileutil import atomic_write_text
from boxmunge.log import log_operation
from boxmunge.manifest import get_all_routes
from boxmunge.paths import BoxPaths


def _access_log_lines() -> list[str]:
    """Caddy access-log directive lines for a site block.

    Emits JSON to a shared host-mounted file (`/var/log/caddy/access.log`,
    bind-mounted from `/opt/boxmunge/caddy/logs`) that the host's CrowdSec
    `crowdsecurity/caddy` parser ingests for HTTP-layer detection. Every site
    block writes to the same path; Caddy dedupes file writers by filename, so
    this is safe. Caddy self-rotates the file (lumberjack), keeping rotation
    out of logrotate — consistent with the rest of the box.
    """
    return [
        "    log {",
        "        output file /var/log/caddy/access.log {",
        "            roll_size 50MiB",
        "            roll_keep 5",
        "        }",
        "        format json",
        "    }",
    ]


def generate_caddy_config(manifest: dict[str, Any]) -> str:
    """Generate a Caddy site block from a project manifest.

    Routes are ordered by specificity (most specific path first).
    Each host gets the same set of routes.
    """
    hosts = manifest["hosts"]
    routes = get_all_routes(manifest)

    host_line = ", ".join(hosts)
    lines = [f"{host_line} {{"]
    lines.extend(_access_log_lines())

    for path, alias, port in routes:
        if path == "/":
            lines.append(f"    handle {{")
            lines.append(f"        reverse_proxy {alias}:{port}")
            lines.append(f"    }}")
        else:
            lines.append(f"    handle {path} {{")
            lines.append(f"        reverse_proxy {alias}:{port}")
            lines.append(f"    }}")

    lines.append("}")
    lines.append("")

    return "\n".join(lines)


def prepare_caddy_config(paths: BoxPaths, manifest: dict[str, Any]) -> None:
    """Generate or copy Caddy site config for a project.

    Writes either the generated site block or, if a host operator has
    placed a project-specific override file, a copy of that override.
    The deploy/promote/resume/upgrade and security-resume flows all use
    this primitive — it lives at module scope (boxmunge.caddy) rather
    than commands/ so cross-command coordination doesn't require a
    `commands/`-to-`commands/` import (audit A-2).
    """
    project_name = manifest["project"]
    site_conf = paths.project_caddy_site(project_name)
    site_conf.parent.mkdir(parents=True, exist_ok=True)

    override = paths.project_caddy_override(project_name)
    # mode=0o644: the Caddy container reads these as a host-mounted volume.
    # The container's UID may not map to the host's deploy UID, so the files
    # must be world-readable. They contain only routing config, no secrets.
    if override.exists():
        atomic_write_text(site_conf, override.read_text(), mode=0o644)
        log_operation(
            "deploy",
            f"Using custom Caddy config from {override.name}",
            paths, project=project_name,
        )
    else:
        config = generate_caddy_config(manifest)
        atomic_write_text(site_conf, config, mode=0o644)


def generate_staging_caddy_config(
    manifest: dict[str, Any],
    auth: tuple[str, str] | None = None,
) -> str:
    """Generate a staging Caddy site block.

    Prefixes all hostnames with 'staging.' and all service aliases with
    '<project>-staging-' to run alongside production.

    If auth is provided as (username, bcrypt_hash), wraps all routes in a
    basicauth block.
    """
    hosts = manifest["hosts"]
    project = manifest["project"]
    routes = get_all_routes(manifest)

    staging_hosts = [f"staging.{h}" for h in hosts]
    host_line = ", ".join(staging_hosts)
    lines = [f"{host_line} {{"]
    lines.extend(_access_log_lines())

    if auth:
        username, password_hash = auth
        lines.append(f"    basicauth {{")
        lines.append(f"        {username} {password_hash}")
        lines.append(f"    }}")

    for path, alias, port in routes:
        staging_alias = alias.replace(f"{project}-", f"{project}-staging-", 1)
        if path == "/":
            lines.append(f"    handle {{")
            lines.append(f"        reverse_proxy {staging_alias}:{port}")
            lines.append(f"    }}")
        else:
            lines.append(f"    handle {path} {{")
            lines.append(f"        reverse_proxy {staging_alias}:{port}")
            lines.append(f"    }}")

    lines.append("}")
    lines.append("")
    return "\n".join(lines)
