"""Dotenv file operations for secrets management."""
from pathlib import Path


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
