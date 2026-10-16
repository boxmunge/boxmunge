# SPDX-License-Identifier: Apache-2.0
"""Canonical path constants for boxmunge.

All paths are relative to a configurable root so tests can use a temp directory.
"""

import re
from pathlib import Path

_VALID_PROJECT_NAME = re.compile(r'[a-z0-9][a-z0-9\-]{0,62}')

# Staging runs as the compose project `<project>-staging`, so a project
# whose own name ends in this suffix would share containers, networks and
# volumes with another project's staging copy. The suffix is reserved.
STAGING_SUFFIX = "-staging"

# Compose project names of the platform's own stacks (/opt/boxmunge/caddy
# and /opt/boxmunge/system, named after their directories). A project with
# one of these names would share that compose project, and its
# `up --remove-orphans` would remove the platform's containers.
RESERVED_PROJECT_NAMES: frozenset[str] = frozenset({"caddy", "system"})


class InvalidProjectName(ValueError):
    """A name that is not, or is no longer, a usable project name.

    A project created before a name was reserved (`<x>-staging`, `caddy`,
    `system`) can no longer be managed. Fleet loops treat this like any
    other unreadable per-project input (boxmunge.fleet): report the project
    loudly and carry on with the rest.
    """


def validate_project_name(name: str) -> None:
    """Validate a project name. Raises InvalidProjectName if invalid.

    Project names must be lowercase alphanumeric with hyphens, 1-63 chars,
    starting with a letter or digit. This prevents path traversal attacks.
    fullmatch, not match: a `$` anchor would accept a trailing newline.
    Names ending in STAGING_SUFFIX are reserved for staging environments,
    and RESERVED_PROJECT_NAMES for the platform's own compose stacks.
    """
    if not isinstance(name, str) or not _VALID_PROJECT_NAME.fullmatch(name):
        raise InvalidProjectName(
            f"Invalid project name: {name!r}. "
            f"Must be lowercase alphanumeric with hyphens, 1-63 chars."
        )
    if name in RESERVED_PROJECT_NAMES:
        raise InvalidProjectName(
            f"Invalid project name: {name!r}. It is reserved for a boxmunge "
            f"platform service. Choose another name."
        )
    if name.endswith(STAGING_SUFFIX):
        raise InvalidProjectName(
            f"Invalid project name: {name!r}. Names ending in "
            f"'{STAGING_SUFFIX}' are reserved: boxmunge runs the staging copy "
            f"of project '{name[:-len(STAGING_SUFFIX)]}' under that name. "
            f"Choose a name without the suffix."
        )

def _checked(name: str) -> str:
    """Return *name* unchanged after validating it as a project name.

    Every BoxPaths method that turns a project name into a path calls this,
    so no caller (CLI, MCP, TUI, timers) can resolve a path outside its
    project by passing "", ".", ".." or a name containing "/".
    """
    validate_project_name(name)
    return name


DEFAULT_ROOT = Path("/opt/boxmunge")


class BoxPaths:
    """Resolve all boxmunge paths from a root directory."""

    def __init__(self, root: Path = DEFAULT_ROOT) -> None:
        self.root = root
        self.bin = root / "bin"
        self.config = root / "config"
        self.config_file = self.config / "boxmunge.yml"
        self.backup_key = self.config / "backup.key"
        # Mounted read-only into the system container at /config/rclone.
        self.rclone_config_dir = self.config / "rclone"
        self.rclone_config = self.rclone_config_dir / "rclone.conf"
        self.version_file = self.config / "version"
        self.system = root / "system"
        self.system_compose = self.system / "compose.yml"
        self.caddy = root / "caddy"
        self.caddy_sites = self.caddy / "sites"
        self.caddyfile = self.caddy / "Caddyfile"
        self.projects = root / "projects"
        self.state = root / "state"
        self.health_state = self.state / "health"
        self.deploy_state = self.state / "deploy"
        self.staging_state = self.state / "staging"
        self.templates = root / "templates" / "project"
        self.docs = root / "docs"
        self.logs = root / "logs"
        self.log_file = self.logs / "boxmunge.log"
        self.inbox = root / "inbox"
        self.inbox_tmp = self.inbox / ".tmp"
        self.inbox_consumed = self.inbox / ".consumed"
        self.host_secrets = self.config / "secrets.env"
        # Writer locks for secrets files. Kept out of the project tree, which
        # a release install prunes, so the lock file never vanishes mid-use.
        self.secrets_locks = self.state / "secrets-locks"
        self.host_secrets_lock = self.secrets_locks / ".host.lock"
        # Host-scoped CVE suppressions — applied across every project on
        # the box. Per-project files at <project>/security/suppressions.yml
        # remain authoritative for project-specific entries and take
        # precedence; this file is for fleet-wide noise such as base-image
        # CVEs whose vulnerable code path is never loaded by any deployed
        # service. Same YAML schema as the per-project file.
        self.host_suppressions = self.config / "suppressions.yml"
        self.stashes = root / "stashes"
        self.canary = root / "canary"
        self.upgrade_state = root / "upgrade-state"
        self.blocklist = self.upgrade_state / "blocklist.json"
        self.probation = self.upgrade_state / "probation.json"
        self.upgrade_lock = self.upgrade_state / "upgrade.lock"
        self.active_slot = self.upgrade_state / "active-slot"
        self.cosign_pub = self.config / "cosign.pub"
        self.container_update_state = self.state / "container-updates"
        self.container_update_lock = self.container_update_state / ".lock"
        # CVE migration grace marker (singleton, fleet-wide).
        # Created lazily on first scan after upgrade; never re-init.
        self.cve_grace_state = self.state / "cve-grace.json"
        # CISA KEV catalog cache (singleton, fleet-wide). Refreshed best-effort
        # before each scan; consumed by the CVE policy engine as the
        # active-exploitation signal.
        self.kev_catalog = self.state / "kev" / "catalog.json"
        # Last auto-update discovery that installed nothing: any security or
        # break-fix release it could not install, and the alert sent for it.
        self.platform_update_state = self.state / "platform-updates.json"
        # Last OS-update check by auto-update, and the alert sent for it.
        self.os_update_state = self.state / "os-updates.json"
        # When notify() last logged that Pushover is not configured.
        self.alerts_unconfigured_state = self.state / "alerts-unconfigured.json"

    def container_update_target_state(self, name: str) -> Path:
        return self.container_update_state / f"{name}.json"

    def project_secrets(self, name: str) -> Path:
        name = _checked(name)
        return self.projects / name / "secrets.env"

    def project_secrets_lock(self, name: str) -> Path:
        name = _checked(name)
        return self.secrets_locks / f"{name}.lock"

    def project_dir(self, name: str) -> Path:
        name = _checked(name)
        return self.projects / name

    def project_manifest(self, name: str) -> Path:
        name = _checked(name)
        return self.projects / name / "manifest.yml"

    def project_compose(self, name: str) -> Path:
        name = _checked(name)
        return self.projects / name / "compose.yml"

    def project_compose_override(self, name: str) -> Path:
        name = _checked(name)
        return self.projects / name / "compose.boxmunge.yml"

    def project_caddy_override(self, name: str) -> Path:
        name = _checked(name)
        return self.projects / name / "caddy.override.conf"

    def project_caddy_site(self, name: str) -> Path:
        name = _checked(name)
        return self.caddy_sites / f"{name}.conf"

    def project_backups(self, name: str) -> Path:
        name = _checked(name)
        return self.projects / name / "backups"

    def project_data(self, name: str) -> Path:
        name = _checked(name)
        return self.projects / name / "data"

    def project_releases(self, name: str) -> Path:
        """Release workspace: incoming bundle trees and code snapshots."""
        name = _checked(name)
        return self.projects / name / ".releases"

    def project_health_state(self, name: str) -> Path:
        name = _checked(name)
        return self.health_state / f"{name}.json"

    def project_deploy_state(self, name: str) -> Path:
        name = _checked(name)
        return self.deploy_state / f"{name}.json"

    def project_paused_state(self, name: str) -> Path:
        name = _checked(name)
        return self.deploy_state / f"{name}.paused.json"

    def project_quarantine_state(self, name: str) -> Path:
        name = _checked(name)
        return self.deploy_state / f"{name}.quarantined.json"

    def project_scan_state(self, name: str) -> Path:
        name = _checked(name)
        return self.state / "scans" / f"{name}.json"

    def project_staging_caddy_site(self, name: str) -> Path:
        name = _checked(name)
        return self.caddy_sites / f"{name}-staging.conf"

    def project_staging_compose_override(self, name: str) -> Path:
        name = _checked(name)
        return self.projects / name / "compose.boxmunge-staging.yml"

    def project_staging_state(self, name: str) -> Path:
        name = _checked(name)
        return self.staging_state / f"{name}.json"

    def project_lock_file(self, name: str) -> Path:
        name = _checked(name)
        return self.state / f"{name}.lock"

    def is_project_pre_registered(self, name: str) -> bool:
        """True if project dir exists but has no manifest (secrets-only)."""
        project_dir = self.project_dir(name)  # validates name
        return project_dir.exists() and not (project_dir / "manifest.yml").exists()
