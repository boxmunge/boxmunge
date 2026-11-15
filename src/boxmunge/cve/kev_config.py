# SPDX-License-Identifier: Apache-2.0
"""The ``kev:`` block of boxmunge.yml: the CISA feed sources and the
optional known-exploited sources beside them."""
from __future__ import annotations

from dataclasses import dataclass

from boxmunge.config import ConfigError
from boxmunge.config_values import found
from boxmunge.cve.kev import KEV_DEFAULT_SOURCES
from boxmunge.host_config_alert import load_for_job
from boxmunge.paths import BoxPaths

_KEYS = {"sources", "enisa", "vulncheck"}


@dataclass(frozen=True)
class KevConfig:
    sources: tuple[str, ...] = KEV_DEFAULT_SOURCES
    enisa_enabled: bool = True
    vulncheck_token: str | None = None


def _sources(block: dict, where: object) -> tuple[str, ...]:
    sources = block["sources"]
    if not isinstance(sources, list) or not sources:
        raise ConfigError(f"'kev.sources' in {where} must be a non-empty list of URLs; "
                          f"remove it to use the defaults")
    bad = [s for s in sources if not (isinstance(s, str) and s.startswith("https://"))]
    if bad:
        raise ConfigError(f"'kev.sources' in {where} must hold https:// URLs, found "
                          f"{', '.join(sorted({found(s) for s in bad}))} that is not one")
    return tuple(sources)


def _enisa_enabled(block: dict, where: object) -> bool:
    if "enisa" not in block:
        return True
    enisa = block["enisa"]
    if (not isinstance(enisa, dict) or set(enisa) != {"enabled"}
            or not isinstance(enisa["enabled"], bool)):
        raise ConfigError(f"'kev.enisa' in {where} must be a mapping with only 'enabled' "
                          f"(true or false), e.g. 'enisa: {{enabled: false}}'; remove it "
                          f"to fetch ENISA's list")
    return enisa["enabled"]


def _vulncheck_token(block: dict, where: object) -> str | None:
    if "vulncheck" not in block:
        return None
    vulncheck = block["vulncheck"]
    token = vulncheck.get("token") if isinstance(vulncheck, dict) else None
    if set(vulncheck if isinstance(vulncheck, dict) else ()) != {"token"} or not (
            isinstance(token, str) and token.strip()):
        raise ConfigError(f"'kev.vulncheck' in {where} must be a mapping with only 'token', "
                          f"a non-empty string; remove it to leave VulnCheck off")
    return token


def kev_config(paths: BoxPaths) -> KevConfig:
    """The ``kev`` settings from boxmunge.yml, or the defaults if it sets none.

    `kev` is the one setting the refresh reads, and it is checked here: a
    mistake in it fails only the KEV refresh, and no other setting does.
    """
    config = load_for_job(paths, "cve-scan")
    if "kev" not in config:
        return KevConfig()
    block = config["kev"]
    where = paths.config_file
    if not isinstance(block, dict) or "sources" not in block or not set(block) <= _KEYS:
        raise ConfigError(
            f"'kev' in {where} must be a mapping with only 'sources' (required), 'enisa' and "
            f"'vulncheck', e.g. 'kev: {{sources: [{KEV_DEFAULT_SOURCES[0]}]}}'; remove it "
            f"to use the defaults")
    return KevConfig(_sources(block, where), _enisa_enabled(block, where),
                     _vulncheck_token(block, where))

