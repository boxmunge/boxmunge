"""Secrets files: the Compose env files behind ``secrets set/get/list/unset``.

A value reaches the container exactly as it was set, and ``get`` prints that
same value. Compose's env-file parser rewrites unquoted values (``$``
interpolates, `` #`` starts a comment, surrounding quotes and whitespace are
stripped), but reads a single-quoted value literally, except that ``\\'``
stands for a quote. So every value is written single-quoted with each ``'``
escaped. A value that form cannot carry (one ending in an odd run of
backslashes, or with such a run before a quote) is refused.

Older boxmunge wrote values unquoted. Such a line is read literally when
Compose reads it as written and the quoted form can carry it (*plain*), and
is re-encoded on the next write.
Any other unquoted line is *legacy*: what containers receive from it depends
on Compose's interpretation, which can draw on the environment, so it is
kept byte for byte (containers keep receiving what they did) until the
operator sets or unsets that key, and ``get`` refuses to report it. So is a
line whose key name boxmunge no longer accepts (Compose still passes it on);
``unset`` removes it by its exact name. boxmunge's own staging-auth keys
keep the old reader's meaning instead (see get_internal_key).

Every read-modify-write holds the file's lock, so concurrent ``set`` and
``unset`` calls from SSH and MCP clients cannot lose each other's changes.
"""
from __future__ import annotations

import re
from contextlib import contextmanager
from dataclasses import dataclass, field
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
    """A secrets file holds a line that cannot be read as KEY=VALUE."""


class QuoteSpanError(SecretsFileError):
    """Old values whose quotes can make Compose read later lines into them."""

    def __init__(self, path: Path, keys: list[str]) -> None:
        super().__init__(
            f"{path}: the stored values of {', '.join(keys)} open a quote that "
            "their line does not close, so Compose can read the lines after them "
            "into those values and any other change could alter other secrets. "
            "Set or unset each of them first."
        )
        self.keys = keys


class LegacySecretError(ValueError):
    """The key's stored line is not literal, so its true value is unknown."""

    def __init__(self, key: str, stored: str) -> None:
        if valid_key(key):
            super().__init__(f"{key} is stored in the old unquoted format")
        else:
            super().__init__(f"{key!r} is not a valid secret key name")
        self.key = key
        self.stored = stored


# boxmunge's own keys (staging basic auth for Caddy), not the app's.
INTERNAL_KEYS = frozenset({"STAGING_AUTH_USER", "STAGING_AUTH_PASS"})


@dataclass(frozen=True)
class Inventory:
    """What a secrets file holds, by how far boxmunge can vouch for it."""

    keys: list[str]       # every key, sorted
    legacy: list[str]     # valid names whose old unquoted value is ambiguous
    misnamed: list[str]   # names current boxmunge refuses (kept as stored)
    migrated: list[str] = field(default_factory=list)  # re-encoded by this write


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


def _plain_unquoted(text: str) -> bool:
    """True if Compose reads this unquoted value exactly as written, and the
    quoted form a rewrite would give it means the same to Compose.

    A plain-looking value that the quoted form cannot carry (an odd run of
    backslashes at its end or before a quote) is not plain: re-encoding it
    would leave an unterminated quote that breaks the whole file.
    """
    return ("$" not in text and " #" not in text and text == text.strip()
            and not text.startswith(("'", '"'))
            and _decode_single_quoted(_encode(text)) == text)


def _may_span_lines(raw: str) -> bool:
    """True unless raw is unquoted or one quoted value closing at line end.

    A value that opens a quote and does not close it exactly at the end of
    its line (left open, or closed early and reopened) can make Compose read
    the following lines into it, so what it makes of every later line
    depends on the file's exact layout.
    """
    text = raw.lstrip()
    if not text.startswith(("'", '"')):
        return False
    escaped = False
    for i, ch in enumerate(text[1:], start=1):
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == text[0]:
            return i != len(text) - 1
    return True


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
            f"invalid secret value for {key}: a value with an odd number of "
            "backslashes at its end or right before a single quote cannot be "
            "passed to containers unchanged; base64-encode it and decode it "
            "in the app"
        )


def valid_key(key: str) -> bool:
    return _KEY_RE.fullmatch(key) is not None


def _parse(path: Path) -> dict[str, _Entry]:
    if not path.exists():
        return {}
    entries: dict[str, _Entry] = {}
    # Split on "\n" only, as Compose does: a value may hold U+2028 and kin,
    # which str.splitlines() would treat as line breaks, and bytes are read
    # untranslated so a stray CR stays visible to the checks below.
    for lineno, line in enumerate(path.read_bytes().decode("utf-8").split("\n"), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, sep, raw = line.partition("=")
        if not sep:
            raise SecretsFileError(
                f"{path} line {lineno} has no '=' (older versions let a newline "
                "into a key or value). Edit the file to fix or remove that "
                "line, then retry."
            )
        if key in entries:
            raise SecretsFileError(
                f"{path} line {lineno} sets {key!r} a second time. Edit the "
                "file to keep only the line you want, then retry."
            )
        if not valid_key(key):
            value = None
        elif raw.startswith("'"):
            value = _decode_single_quoted(raw)
        else:
            value = raw if _plain_unquoted(raw) else None
        entries[key] = _Entry(line, value)
    return entries


def _inventory(entries: dict[str, _Entry], migrated: list[str] | None = None) -> Inventory:
    unknown = sorted(k for k, e in entries.items() if e.value is None)
    return Inventory(
        keys=sorted(entries),
        legacy=[k for k in unknown if valid_key(k)],
        misnamed=[k for k in unknown if not valid_key(k)],
        migrated=sorted(migrated or []),
    )


def get_key(secrets: SecretsFile, key: str) -> str | None:
    """The key's value, None if unset. Raises LegacySecretError if unknown."""
    entry = _parse(secrets.path).get(key)
    if entry is None:
        return None
    if entry.value is None:
        raise LegacySecretError(key, entry.line.partition("=")[2])
    return entry.value


def get_internal_key(secrets: SecretsFile, key: str) -> str | None:
    """Like get_key, for INTERNAL_KEYS: boxmunge's own, not the app's.

    What such a key meant was defined by boxmunge's old reader, not by
    Compose, so its old unquoted line was never ambiguous: that reading
    (line stripped, then one pair of matching surrounding quotes removed)
    is kept for it, and stage keeps working after an upgrade.
    """
    if key not in INTERNAL_KEYS:
        raise ValueError(f"{key} is not one of boxmunge's own keys")
    entry = _parse(secrets.path).get(key)
    if entry is None:
        return None
    if entry.value is not None:
        return entry.value
    value = entry.line.strip().partition("=")[2]
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
        value = value[1:-1]
    return value


def list_keys(secrets: SecretsFile) -> list[str]:
    return sorted(_parse(secrets.path))


def inventory(secrets: SecretsFile) -> Inventory:
    return _inventory(_parse(secrets.path))


def _rewrite(secrets: SecretsFile, key: str, value: str | None) -> Inventory:
    """Set (or with None, remove) key under the lock.

    Returns the file's inventory after the write, with the other keys whose
    plain unquoted lines were re-encoded, so callers need not re-read it.
    """
    with secrets.locked():
        entries = _parse(secrets.path)
        spanning = sorted(k for k, e in entries.items()
                          if e.value is None and _may_span_lines(e.line.partition("=")[2]))
        # Clearing one of them is always allowed, so they can go one at a time.
        if spanning and key not in spanning:
            raise QuoteSpanError(secrets.path, spanning)
        removed = entries.pop(key, None)
        migrated = []
        for k, entry in entries.items():
            if entry.value is not None and entry.line != f"{k}={_encode(entry.value)}":
                entries[k] = _Entry(f"{k}={_encode(entry.value)}", entry.value)
                migrated.append(k)
        if value is not None:
            entries[key] = _Entry(f"{key}={_encode(value)}", value)
        if value is not None or removed is not None or migrated:
            content = "".join(entries[k].line + "\n" for k in sorted(entries))
            atomic_write_text(secrets.path, content, mode=0o600)
    return _inventory(entries, migrated)


def set_key(secrets: SecretsFile, key: str, value: str) -> Inventory:
    """Store value literally."""
    validate_secret(key, value)
    return _rewrite(secrets, key, value)


def unset_key(secrets: SecretsFile, key: str) -> Inventory:
    """Remove key if present, by its exact stored name."""
    return _rewrite(secrets, key, None)
