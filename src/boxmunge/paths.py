# SPDX-License-Identifier: Apache-2.0
"""Canonical path constants for boxmunge.

All paths are relative to a configurable root so tests can use a temp directory.
"""

import re
from pathlib import Path

_VALID_PROJECT_NAME = re.compile(r'^[a-z0-9][a-z0-9\-]{0,62}$')


def validate_project_name(name: str) -> None:
    """Validate a project name. Raises ValueError if invalid.

    Project names must be lowercase alphanumeric with hyphens, 1-63 chars,
    starting with a letter or digit. This prevents path traversal attacks.
    """
    if not _VALID_PROJECT_NAME.match(name):
        raise ValueError(
            f"Invalid project name: {name!r}. "
            f"Must be lowercase alphanumeric with hyphens, 1-63 chars."
        )

DEFAULT_ROOT = Path("/opt/boxmunge")


class BoxPaths:
    """Resolve all boxmunge paths from a root directory."""

    def __init__(self, root: Path = DEFAULT_ROOT) -> None:
        self.root = root
        self.bin = root / "bin"
        self.config = root / "config"
        self.config_file = self.config / "boxmunge.yml"
        self.backup_key = self.config / "backup.key"
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

    def container_update_target_state(self, name: str) -> Path:
        return self.container_update_state / f"{name}.json"

    def project_secrets(self, name: str) -> Path:
        return self.projects / name / "secrets.env"

    def project_dir(self, name: str) -> Path:
        return self.projects / name

    def project_manifest(self, name: str) -> Path:
        return self.projects / name / "manifest.yml"

    def project_compose(self, name: str) -> Path:
        return self.projects / name / "compose.yml"

    def project_compose_override(self, name: str) -> Path:
        return self.projects / name / "compose.boxmunge.yml"

    def project_caddy_override(self, name: str) -> Path:
        return self.projects / name / "caddy.override.conf"

    def project_caddy_site(self, name: str) -> Path:
        return self.caddy_sites / f"{name}.conf"

    def project_backups(self, name: str) -> Path:
        return self.projects / name / "backups"

    def project_data(self, name: str) -> Path:
        return self.projects / name / "data"

    def project_health_state(self, name: str) -> Path:
        return self.health_state / f"{name}.json"

    def project_deploy_state(self, name: str) -> Path:
        return self.deploy_state / f"{name}.json"

    def project_paused_state(self, name: str) -> Path:
        return self.deploy_state / f"{name}.paused.json"

    def project_quarantine_state(self, name: str) -> Path:
        return self.deploy_state / f"{name}.quarantined.json"

    def project_scan_state(self, name: str) -> Path:
        return self.state / "scans" / f"{name}.json"

    def project_staging_caddy_site(self, name: str) -> Path:
        return self.caddy_sites / f"{name}-staging.conf"

    def project_staging_compose_override(self, name: str) -> Path:
        return self.projects / name / "compose.boxmunge-staging.yml"

    def project_staging_state(self, name: str) -> Path:
        return self.staging_state / f"{name}.json"

    def project_lock_file(self, name: str) -> Path:
        return self.state / f"{name}.lock"

    def is_project_pre_registered(self, name: str) -> bool:
        """True if project dir exists but has no manifest (secrets-only)."""
        project_dir = self.project_dir(name)
        return project_dir.exists() and not (project_dir / "manifest.yml").exists()
