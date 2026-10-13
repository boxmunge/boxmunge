# SPDX-License-Identifier: Apache-2.0
"""gitignore-style patterns for .boxmungeignore.

Supported syntax, matching gitignore:
  - blank lines and lines starting with '#' are ignored;
  - a leading '!' re-includes a path an earlier pattern (or a default
    exclude) would drop;
  - a trailing '/' matches directories only;
  - a pattern containing '/' (other than a trailing one) is anchored to the
    project root, a leading '/' only anchors;
  - '*' and '?' never match '/', '**' matches across directories, and
    '[abc]' / '[!abc]' are character classes.
As in git, a file inside an excluded directory cannot be re-included.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


class IgnoreFileError(Exception):
    """Raised for a .boxmungeignore pattern that cannot be parsed."""


@dataclass(frozen=True)
class _Rule:
    pattern: str
    regex: re.Pattern[str]
    negated: bool
    dir_only: bool


def _translate(glob: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(glob):
        c = glob[i]
        if glob.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif glob.startswith("**", i):
            out.append(".*")
            i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c == "[":
            end = glob.find("]", i + 1)
            if end == -1:
                raise IgnoreFileError(f"unclosed '[' in pattern {glob!r}")
            body = glob[i + 1:end]
            if body.startswith("!"):
                body = "^" + body[1:]
            out.append("[" + body.replace("\\", "\\\\") + "]")
            i = end + 1
        else:
            out.append(re.escape(c))
            i += 1
    return "".join(out)


def _compile(line: str) -> _Rule | None:
    raw = line.rstrip()
    if not raw or raw.startswith("#"):
        return None
    negated = raw.startswith("!")
    body = raw[1:] if negated else raw
    dir_only = body.endswith("/")
    body = body.rstrip("/")
    if not body:
        raise IgnoreFileError(f"empty pattern in line {line!r}")
    anchored = "/" in body
    body = body.lstrip("/")
    prefix = "^" if anchored else "^(?:.*/)?"
    return _Rule(raw, re.compile(prefix + _translate(body) + "$"), negated, dir_only)


class IgnoreRules:
    """An ordered list of patterns; the last matching pattern wins."""

    def __init__(self, lines: list[str]) -> None:
        self._rules = [r for r in (_compile(line) for line in lines) if r is not None]

    @classmethod
    def from_file(cls, path: Path) -> IgnoreRules:
        if not path.is_file():
            return cls([])
        return cls(path.read_text(encoding="utf-8").splitlines())

    def match(self, rel: str, is_dir: bool) -> bool | None:
        """True if ignored, False if explicitly re-included, None if no rule matches."""
        verdict: bool | None = None
        for rule in self._rules:
            if rule.dir_only and not is_dir:
                continue
            if rule.regex.match(rel):
                verdict = not rule.negated
        return verdict
