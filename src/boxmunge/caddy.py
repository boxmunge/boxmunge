"""Generate Caddy site configuration from a project manifest."""

import os
from pathlib import Path
from typing import Any

from boxmunge.caddy_journal import MAX_SITE_BYTES, write_site
from boxmunge.fs_nofollow import open_resolved_nofollow
from boxmunge.docker import caddy_config_lock
from boxmunge.log import log_operation
from boxmunge.manifest import get_all_routes
from boxmunge.paths import BoxPaths


# Access-log fields that carry text from a client or an upstream, each cut to
# this many characters; every other such field is dropped. CrowdSec's docker
# source drops a line over 64 KiB and loses the lines after it while it
# restarts the tail, and Caddy JSON-escapes a byte into up to six. So no
# request or response header is logged (any number, at any length), nor the
# TLS details (a client's SNI runs to 64 KiB): only the User-Agent, appended
# as a field of its own. A test walks every field a real Caddy emits and
# fails on one that is neither here nor bounded by Caddy itself.
ACCESS_LOG_FIELD_LIMITS = {
    "request>uri": 2048,
    "request>host": 256,
    "request>method": 32,
    "user_agent": 512,
    "user_id": 256,
}
ACCESS_LOG_DROPPED = ("request>headers", "request>tls", "resp_headers")


def _longer_than(limit: int) -> str:
    """A regexp capturing the first `limit` characters of a longer value and
    matching nothing shorter, which the filter then leaves untouched. Fixed
    widths, not `.{0,n}`: a bounded range costs Go's regexp engine far more
    per request. Go refuses a repeat count above 1000, so a longer limit is
    a run of such groups."""
    chunks = [1000] * (limit // 1000) + ([limit % 1000] if limit % 1000 else [])
    return "^(" + "".join(f".{{{n}}}" for n in chunks) + ").+$"


def _access_log_lines() -> list[str]:
    """Caddy access-log directive lines for a site block.

    JSON on the container's stdout (Caddy's own runtime log stays on
    stderr). The host's CrowdSec reads it through the Docker API
    (`source: docker`, stdout only) with boxmunge's own parser
    (bootstrap/crowdsec-acquis.sh): the hub's caddy parser needs the request
    headers logged. Never a file: one would sit in a directory the remapped
    Caddy owns, and root CrowdSec would open whatever Caddy left there (a
    FIFO, a link to a root-only file). caddy/compose.yml's json-file logging
    rotates it.
    """
    fields = [f"                {name} delete" for name in ACCESS_LOG_DROPPED]
    fields += [f'                {name} regexp "{_longer_than(limit)}" "${{1}}"'
               for name, limit in ACCESS_LOG_FIELD_LIMITS.items()]
    return [
        "    log_append user_agent {http.request.header.User-Agent}",
        "    log {",
        "        output stdout",
        "        format filter {",
        "            wrap json",
        "            fields {",
        *fields,
        "            }",
        "        }",
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


def site_config(paths: BoxPaths, project: str,
                manifest: dict[str, Any]) -> tuple[str, Path | None]:
    """(content, override) of ``project``'s production site config: the
    operator's caddy.override.conf verbatim when it exists, else the block
    generated from ``manifest``; ``override`` is the file used, or None.
    prepare_caddy_config writes this, and diff previews it."""
    override = paths.project_caddy_override(project)
    text = read_override(override)
    if text is not None:
        return text, override
    return generate_caddy_config(manifest), None


def read_override(override: Path) -> str | None:
    """The text of a project's caddy.override.conf, or None if there is
    none. The project directory is deploy-writable and root reads this under
    sudo deploy/promote/rollback/resume and the upgrade, so it must resolve
    inside the project (a link into repo/, say, is fine; one out of the
    project is refused), is opened along its resolved path without
    following a link swapped in at any depth or blocking on a FIFO, and is
    capped at the size of a site file. Raises OSError naming the fix."""
    def unusable(what: str) -> OSError:
        return OSError(f"{override} {what}. Make it a regular file in the project "
                       f"holding the site block, or remove it to use the generated "
                       f"site config.")
    if not os.path.lexists(override):
        return None
    project = Path(os.path.realpath(override.parent))
    target = Path(os.path.realpath(override))
    if not target.is_relative_to(project):
        raise unusable(f"is a link to {target}, outside the project, which boxmunge "
                       f"does not follow")
    try:
        fd = open_resolved_nofollow(target, os.O_RDONLY)
    except FileNotFoundError as e:
        raise unusable(f"is a link to {target}, which does not exist") from e
    except OSError as e:
        raise unusable("is not a regular file, or a link on its way was swapped") from e
    with os.fdopen(fd, "rb") as f:
        data = f.read(MAX_SITE_BYTES + 1)
    if len(data) > MAX_SITE_BYTES:
        raise unusable(f"is larger than {MAX_SITE_BYTES} bytes")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise unusable("is not UTF-8 text") from e


def override_refusal(paths: BoxPaths, project: str) -> str | None:
    """Why ``project``'s caddy.override.conf cannot be used, or None."""
    try:
        read_override(paths.project_caddy_override(project))
    except OSError as e:
        return str(e)
    return None


def prepare_caddy_config(paths: BoxPaths, manifest: dict[str, Any]) -> str:
    """Generate or copy Caddy site config for a project, and return the
    text written. A caller that needs the text takes it from here: deploy
    can replace a name in caddy/sites, so reading the file back as root
    reads whatever deploy put there.

    Writes either the generated site block or, if a host operator has
    placed a project-specific override file, a copy of that override.
    The deploy/promote/resume/upgrade and security-resume flows all use
    this primitive — it lives at module scope (boxmunge.caddy) rather
    than commands/ so cross-command coordination doesn't require a
    `commands/`-to-`commands/` import (audit A-2).

    The previous content is journaled so a failed Caddy validation on the
    next reload restores it (see `caddy_journal`).
    """
    project_name = manifest["project"]
    site_conf = paths.project_caddy_site(project_name)
    content, override = site_config(paths, project_name, manifest)
    if override is not None:
        log_operation(
            "deploy",
            f"Using custom Caddy config from {override.name}",
            paths, project=project_name,
        )
    with caddy_config_lock(paths.state):
        write_site(paths.caddy, site_conf, content)
    return content


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
