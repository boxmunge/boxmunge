"""Generate Caddy site configuration from a project manifest."""

from typing import Any

from boxmunge.manifest import get_all_routes


def generate_caddy_config(manifest: dict[str, Any]) -> str:
    """Generate a Caddy site block from a project manifest.

    Routes are ordered by specificity (most specific path first).
    Each host gets the same set of routes.
    """
    hosts = manifest["hosts"]
    routes = get_all_routes(manifest)

    host_line = ", ".join(hosts)
    lines = [f"{host_line} {{"]

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


def generate_staging_caddy_config(manifest: dict[str, Any]) -> str:
    """Generate a staging Caddy site block.

    Prefixes all hostnames with 'staging.' and all service aliases with
    '<project>-staging-' to run alongside production.
    """
    hosts = manifest["hosts"]
    project = manifest["project"]
    routes = get_all_routes(manifest)

    staging_hosts = [f"staging.{h}" for h in hosts]
    host_line = ", ".join(staging_hosts)
    lines = [f"{host_line} {{"]

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
