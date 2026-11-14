# SPDX-License-Identifier: Apache-2.0
"""The boxmunge.yml opt-out from the version-check service, and what it costs.

``version_check: {enabled: false}`` stops every call the box makes to the
service: update checks (auto-update's and a plain ``upgrade``'s, and the
GitHub fallback with them) and failure reports. The box then discovers no
releases at all, so no security release reaches it unattended. Discovery,
the failure report, auto-update, ``health`` (platform-updates) and
``doctor`` all read the setting here and say so in the same words.
"""
from __future__ import annotations

import yaml

from boxmunge.config import load_config, version_check_enabled
from boxmunge.paths import BoxPaths

RELEASES_PAGE = "https://github.com/boxmunge/boxmunge/releases"

OFF = ("version checks are off (version_check.enabled: false in boxmunge.yml), so this "
       "box discovers no releases and installs no security or break-fix release "
       "automatically. Watch " + RELEASES_PAGE + " and install a release with "
       "`upgrade --target X.Y.Z`, or set version_check.enabled: true to discover them again")


def version_checks_off(paths: BoxPaths) -> bool:
    """True if boxmunge.yml turns version checks off. Raises ConfigError
    when it cannot be read: whether the operator opted out is then unknown,
    and nothing may be sent. No other setting is read, so none stops the
    discovery of an upgrade."""
    return not version_check_enabled(load_config(paths))


NOT_CHOSEN = ("boxmunge.yml has no version_check setting, so nobody recorded a choice and the "
              "default (checks on) applies. Tell the operator what the version check sends "
              "(`agent-help rules`), ask whether to keep it, then set version_check.enabled "
              "to true or false in boxmunge.yml (as root)")


def version_check_unchosen(paths: BoxPaths) -> bool:
    """True if boxmunge.yml has no version_check key: nobody chose. The
    loaded config cannot say so, it has the default merged in. Only called
    once load_config has read the file, so a failure here is a real error."""
    raw = yaml.safe_load(paths.config_file.read_text()) or {}
    return "version_check" not in raw
