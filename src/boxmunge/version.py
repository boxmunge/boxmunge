# SPDX-License-Identifier: Apache-2.0
"""Git-aware version tracking for boxmunge.

Version string format: <semver>+<commit-hash>
Example: 0.2.0+abc1234

Semver drives migration decisions. Commit hash provides traceability.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

FALLBACK_VERSION = "0.0.0"


def parse_version_string(version: str) -> tuple[str, str | None]:
    """Parse 'semver+commit' into (semver, commit). Returns (FALLBACK, None) for empty."""
    if not version.strip():
        return FALLBACK_VERSION, None
    if "+" in version:
        semver, commit = version.split("+", 1)
        return semver, commit
    return version.strip(), None


def format_version_string(semver: str, commit: str | None = None) -> str:
    """Format semver and optional commit into a version string."""
    if commit:
        return f"{semver}+{commit}"
    return semver


def read_installed_version(paths: BoxPaths) -> str:
    """Read the installed version from the version file."""
    if not paths.version_file.exists():
        return FALLBACK_VERSION
    return paths.version_file.read_text().strip()


def write_installed_version(
    paths: BoxPaths, semver: str, commit: str | None = None
) -> None:
    """Write the version string to the version file."""
    paths.version_file.parent.mkdir(parents=True, exist_ok=True)
    paths.version_file.write_text(format_version_string(semver, commit) + "\n")


def get_build_version() -> str:
    """Get version from package metadata + git commit if available."""
    from importlib.metadata import version, PackageNotFoundError
    import subprocess

    try:
        semver = version("boxmunge-server")
    except PackageNotFoundError:
        semver = FALLBACK_VERSION

    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, check=True, timeout=5,
        )
        commit = result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        commit = None

    return format_version_string(semver, commit)
