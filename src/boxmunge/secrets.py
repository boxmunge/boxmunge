"""Dotenv file operations for secrets management."""
import re
from pathlib import Path

# A key is an environment-variable name. A value may hold anything printable
# (tabs included) but no other control character: a newline would start a
# new KEY=VALUE line in the env file, and CR, NUL or escapes corrupt it.
_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_FORBIDDEN_IN_VALUE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")


def validate_secret(key: str, value: str) -> None:
    """Raise ValueError unless key and value are safe to write as one line."""
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


def read_dotenv(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    result = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        result[key.strip()] = value
    return result


def write_dotenv(path: Path, data: dict[str, str]) -> None:
    from boxmunge.fileutil import atomic_write_text
    content = "".join(f"{k}={v}\n" for k, v in sorted(data.items()))
    atomic_write_text(path, content, mode=0o600)


def set_key(path: Path, key: str, value: str) -> None:
    validate_secret(key, value)
    data = read_dotenv(path)
    data[key] = value
    write_dotenv(path, data)


def get_key(path: Path, key: str) -> str | None:
    return read_dotenv(path).get(key)


def unset_key(path: Path, key: str) -> None:
    data = read_dotenv(path)
    data.pop(key, None)
    write_dotenv(path, data)


def list_keys(path: Path) -> list[str]:
    return sorted(read_dotenv(path).keys())
