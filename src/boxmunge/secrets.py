"""Secrets files: the Compose env files behind ``secrets set/get/list/unset``.

A value reaches the container exactly as it was set, and ``get`` prints that
same value. Compose's env-file parser rewrites unquoted values (``$``
interpolates, `` #`` starts a comment, surrounding quotes and whitespace are
stripped), but reads a single-quoted value literally, except that ``\\'``
stands for a quote. So every value is written single-quoted with each ``'``
escaped. A value that form cannot carry (one ending in an odd run of
backslashes, or with such a run before a quote) is refused.

Older boxmunge wrote values unquoted. Such a line is read literally when
Compose reads it as written (*plain*), and re-encoded on the next write.
Any other unquoted line is *legacy*: what containers receive from it depends
on Compose's interpretation, which can draw on the environment, so it is
kept byte for byte (containers keep receiving what they did) until the
operator sets or unsets that key, and ``get`` refuses to report it.

Every read-modify-write holds the file's lock, so concurrent ``set`` and
``unset`` calls from SSH and MCP clients cannot lose each other's changes.
"""
from __future__ import annotations

import re
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

from boxmunge.fileutil import atomic_write_text, exclusive_lock

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

# A key is an environment-variable name. A value may hold anything printable
# (tabs included) but no other control character: a newline would start a
# new KEY=VALUE line in the env file, and CR, NUL or escapes corrupt it.
_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_FORBIDDEN_IN_VALUE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")


class SecretsFileError(ValueError):
    """A secrets file holds a line no boxmunge version writes."""


class LegacySecretError(ValueError):
    """The key's stored value is not literal, so its true value is unknown."""

    def __init__(self, key: str, stored: str) -> None:
        super().__init__(f"{key} is stored in the old unquoted format")
        self.key = key
        self.stored = stored


@dataclass(frozen=True)
class SecretsFile:
    """A secrets env file and the lock serialising its writers."""

    path: Path
    lock_path: Path

    @classmethod
    def host(cls, paths: "BoxPaths") -> "SecretsFile":
        return cls(paths.host_secrets, paths.host_secrets_lock)

    @classmethod
    def project(cls, paths: "BoxPaths", name: str) -> "SecretsFile":
        return cls(paths.project_secrets(name), paths.project_secrets_lock(name))

    @contextmanager
    def locked(self) -> Iterator[None]:
        with exclusive_lock(self.lock_path):
            yield


@dataclass(frozen=True)
class _Entry:
    line: str           # as stored, without the newline
    value: str | None   # the literal value; None for a legacy line


def _encode(value: str) -> str:
    return "'" + value.replace("'", "\\'") + "'"


def _decode_single_quoted(text: str) -> str | None:
    """The value Compose reads from ``'...'`` spanning all of text, else None.

    Mirrors Compose's dotenv parser: a backslash escapes only the quote;
    before any other character, the backslash is kept.
    """
    if not text.startswith("'"):
        return None
    out: list[str] = []
    escaped = False
    for i, ch in enumerate(text[1:], start=1):
        if ch == "'" and not escaped:
            return "".join(out) if i == len(text) - 1 else None
        if escaped:
            escaped = False
            out.append(ch if ch == "'" else "\\" + ch)
        elif ch == "\\":
            escaped = True
        else:
            out.append(ch)
    return None


def _reads_literally_unquoted(text: str) -> bool:
    """True if Compose reads this unquoted value exactly as written."""
    return ("$" not in text and " #" not in text and text == text.strip()
            and not text.startswith(("'", '"')))


def validate_secret(key: str, value: str) -> None:
    """Raise ValueError unless key and value can be stored literally."""
    if not _KEY_RE.fullmatch(key):
        raise ValueError(
            f"invalid secret key {key!r}: use letters, digits and underscores, "
            "not starting with a digit"
        )
    bad = _FORBIDDEN_IN_VALUE.search(value)
    if bad:
        raise ValueError(
            f"invalid secret value for {key}: contains control character "
            f"{bad.group()!r}; newlines and other control characters are not allowed"
        )
    if _decode_single_quoted(_encode(value)) != value:
        raise ValueError(
            f"invalid secret value for {key}: a value that ends in a backslash, "
            "or has an odd number of backslashes before a single quote, cannot "
            "be passed to containers unchanged; base64-encode it and decode it "
            "in the app"
        )


def _parse(path: Path) -> dict[str, _Entry]:
    if not path.exists():
        return {}
    entries: dict[str, _Entry] = {}
    for lineno, line in enumerate(path.read_text().splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, sep, raw = line.partition("=")
        if not sep or not _KEY_RE.fullmatch(key) or key in entries:
            problem = "repeats key " + key if key in entries else "is not KEY=VALUE"
            raise SecretsFileError(
                f"{path} line {lineno} {problem}, which boxmunge never writes. "
                "Edit the file to fix or remove that line, then retry."
            )
        if raw.startswith("'"):
            value = _decode_single_quoted(raw)
        else:
            value = raw if _reads_literally_unquoted(raw) else None
        entries[key] = _Entry(line, value)
    return entries


def get_key(secrets: SecretsFile, key: str) -> str | None:
    """The key's value, None if unset. Raises LegacySecretError if unknown."""
    entry = _parse(secrets.path).get(key)
    if entry is None:
        return None
    if entry.value is None:
        raise LegacySecretError(key, entry.line.partition("=")[2])
    return entry.value


def list_keys(secrets: SecretsFile) -> list[str]:
    return sorted(_parse(secrets.path))


def legacy_keys(secrets: SecretsFile) -> list[str]:
    """Keys stored unquoted in a form Compose does not read literally."""
    return sorted(k for k, e in _parse(secrets.path).items() if e.value is None)


def _rewrite(secrets: SecretsFile, key: str, value: str | None) -> list[str]:
    """Set (or with None, remove) key under the lock.

    Returns the other keys whose plain unquoted lines were re-encoded.
    """
    with secrets.locked():
        entries = _parse(secrets.path)
        removed = entries.pop(key, None)
        migrated = []
        for k, entry in entries.items():
            if entry.value is not None and entry.line != f"{k}={_encode(entry.value)}":
                entries[k] = _Entry(f"{k}={_encode(entry.value)}", entry.value)
                migrated.append(k)
        if value is None and removed is None and not migrated:
            return []
        if value is not None:
            entries[key] = _Entry(f"{key}={_encode(value)}", value)
        content = "".join(entries[k].line + "\n" for k in sorted(entries))
        atomic_write_text(secrets.path, content, mode=0o600)
    return sorted(migrated)


def set_key(secrets: SecretsFile, key: str, value: str) -> list[str]:
    """Store value literally. Returns keys re-encoded from the old format."""
    validate_secret(key, value)
    return _rewrite(secrets, key, value)


def unset_key(secrets: SecretsFile, key: str) -> list[str]:
    """Remove key if present. Returns keys re-encoded from the old format."""
    return _rewrite(secrets, key, None)
