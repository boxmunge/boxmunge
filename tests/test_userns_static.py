"""Only the system container leaves the remapped namespace (spec section 2)."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
_SHIPPED = ("bootstrap", "caddy", "canary", "config", "sample-project", "scripts",
            "src", "system", "templates")
_USERNS_FLAG = re.compile(r"--userns(?!-remap)\b")


def _shipped_files():
    for top in _SHIPPED:
        yield from (p for p in (REPO / top).rglob("*") if p.is_file()
                    and "__pycache__" not in p.parts)
    yield REPO / "install.sh"


def _has_userns_mode(node) -> bool:
    if isinstance(node, dict):
        return "userns_mode" in node or any(_has_userns_mode(v) for v in node.values())
    if isinstance(node, list):
        return any(_has_userns_mode(v) for v in node)
    return False


def test_only_the_system_compose_file_sets_userns_mode() -> None:
    found = set()
    for path in _shipped_files():
        if path.suffix in (".yml", ".yaml"):
            for doc in yaml.safe_load_all(path.read_text()):
                if _has_userns_mode(doc):
                    found.add(str(path.relative_to(REPO)))
    assert found == {"system/compose.yml"}, found


def test_no_shipped_code_passes_userns_to_docker() -> None:
    offenders = [str(p.relative_to(REPO)) for p in _shipped_files()
                 if p.suffix in (".py", ".sh", "") and _USERNS_FLAG.search(
                     p.read_text(errors="replace"))]
    assert offenders == []
