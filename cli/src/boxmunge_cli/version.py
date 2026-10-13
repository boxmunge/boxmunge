# SPDX-License-Identifier: Apache-2.0
"""Compare PEP 440 release versions (the subset boxmunge publishes).

Accepts N(.N)*, an optional pre-release (aN, bN, rcN), .postN, .devN and a
+local label, so pre-releases such as 0.2.0rc1 or 0.11.0.dev3 compare
correctly instead of crashing. Anything else is rejected.
"""

from __future__ import annotations

import re

_VERSION = re.compile(
    r"v?(?P<release>\d+(?:\.\d+)*)"
    r"(?:[-_.]?(?P<pre_kind>a|b|rc)[-_.]?(?P<pre_n>\d+))?"
    r"(?:[-_.]?post[-_.]?(?P<post>\d+))?"
    r"(?:[-_.]?dev[-_.]?(?P<dev>\d+))?"
    r"(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?",
    re.IGNORECASE,
)
_PRE_ORDER = {"a": 0, "b": 1, "rc": 2}

VersionKey = tuple


def parse_version(text: object) -> VersionKey:
    """A sortable key for a version string. Raises ValueError if malformed."""
    if not isinstance(text, str):
        raise ValueError(f"version must be a string, got {text!r}")
    m = _VERSION.fullmatch(text.strip())
    if m is None:
        raise ValueError(f"not a valid version: {text!r}")
    release = [int(x) for x in m.group("release").split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    if m.group("pre_kind"):
        pre = (0, _PRE_ORDER[m.group("pre_kind").lower()], int(m.group("pre_n")))
    elif m.group("dev") and not m.group("post"):
        pre = (-1,)  # 1.0.dev1 sorts before 1.0a1
    else:
        pre = (1,)
    post = int(m.group("post")) + 1 if m.group("post") else 0
    dev = (0, int(m.group("dev"))) if m.group("dev") else (1,)
    return (tuple(release), pre, post, dev)
