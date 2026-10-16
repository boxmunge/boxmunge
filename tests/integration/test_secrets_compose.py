"""Integration: secrets reach Compose exactly as set (real `docker compose config`).

`secrets get` and the container must agree, byte for byte, for every value
`secrets set` accepts. Compose's reading is taken from `config --format json`,
which escapes each literal `$` as `$$` in its output; that is undone here.
"""
from __future__ import annotations

import json
import os
import random
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

from boxmunge.commands.secrets_cmd import run_secrets
from boxmunge.paths import BoxPaths
from boxmunge.secrets import SecretsFile, get_key, list_keys, set_key

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not on PATH"),
]

# Set in Compose's environment so an interpolated ${...} would visibly change.
_INTERPOLATION_ENV = {"BOXMUNGE_SECRETS_PROBE": "INJECTED"}

VALUES = {
    "DOLLAR_BRACE": "pa${BOXMUNGE_SECRETS_PROBE}ss",
    "DOLLAR_BARE": "$BOXMUNGE_SECRETS_PROBE",
    "DOLLAR_DOUBLE": "cost$$5",
    "HASH": "alpha # omega",
    "HASH_LEADING": "#leading",
    "SINGLE_QUOTE": "it's",
    "SINGLE_QUOTED": "'whole'",
    "DOUBLE_QUOTED": '"abc"',
    "BACKSLASHES": "C:\\dir\\file \\n \\t \\\\x",
    "EVEN_BEFORE_QUOTE": "esc\\\\'q",
    "EVEN_AT_END": "end\\\\",
    "PADDED": "  padded  ",
    "TABS": "\ta\tb\t",
    "EQUALS": "=a=b=",
    "UNICODE": "caf\u00e9 \u00a0\U0001f600",
    "EMPTY": "",
    "URL": "postgres://u:p@h:5432/db?sslmode=require&x=1",
}


def _compose_environment(tmp_path: Path, env_files: list[str]) -> dict[str, str]:
    compose = tmp_path / "compose.yml"
    compose.write_text(
        "services:\n  web:\n    image: alpine:3.20\n    env_file:\n"
        + "".join(f"      - {json.dumps(f)}\n" for f in env_files)
    )
    result = subprocess.run(
        ["docker", "compose", "-p", f"bmsecrets-{uuid.uuid4().hex[:10]}",
         "-f", str(compose), "config", "--format", "json"],
        capture_output=True, text=True, cwd=tmp_path,
        env={**os.environ, **_INTERPOLATION_ENV},
    )
    assert result.returncode == 0, result.stderr
    env = json.loads(result.stdout)["services"]["web"].get("environment", {})
    return {k: v.replace("$$", "$") for k, v in env.items()}


def test_every_accepted_value_reaches_compose_unchanged(tmp_path: Path) -> None:
    sf = SecretsFile(tmp_path / "secrets.env", tmp_path / "secrets.lock")
    for key, value in VALUES.items():
        set_key(sf, key, value)
    seen = _compose_environment(tmp_path, ["secrets.env"])
    assert seen == VALUES
    assert {k: get_key(sf, k) for k in list_keys(sf)} == VALUES


def test_cli_project_and_host_scopes_reach_compose_unchanged(tmp_path: Path) -> None:
    paths = BoxPaths(root=tmp_path / "bm")
    paths.projects.mkdir(parents=True)
    assert run_secrets(["set", "--host", f"HOST_TOKEN={VALUES['DOLLAR_BRACE']}"], paths) == 0
    assert run_secrets(["set", "myapp", f"DB_PASS={VALUES['EVEN_BEFORE_QUOTE']}"], paths) == 0
    project_dir = paths.project_dir("myapp")
    seen = _compose_environment(project_dir, [str(paths.host_secrets), "./secrets.env"])
    assert seen == {"HOST_TOKEN": VALUES["DOLLAR_BRACE"], "DB_PASS": VALUES["EVEN_BEFORE_QUOTE"]}


def test_whatever_boxmunge_reads_as_a_value_compose_reads_the_same(tmp_path: Path) -> None:
    """Fuzz both the quoted form and old unquoted lines: any line the reader
    reports a value for (rather than flagging it legacy) must mean that same
    value to Compose. This pins the reader to Compose's parser."""
    rng = random.Random(1316)
    alphabet = ["a", "Z", "'", "\\", '"', "$", "#", " ", "\t", "{", "}", "=", "\u00e9"]
    sf = SecretsFile(tmp_path / "secrets.env", tmp_path / "secrets.lock")
    lines = []
    for i in range(400):
        body = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 8)))
        lines.append(f"K{i}='{body}'" if i % 2 else f"K{i}={body}")
    readable = []
    for line in lines:
        sf.path.write_text(line + "\n")
        key = line.partition("=")[0]
        try:
            get_key(sf, key)
        except ValueError:
            continue
        readable.append(line)
    assert len(readable) > 100
    sf.path.write_text("".join(line + "\n" for line in readable))
    ours = {k: get_key(sf, k) for k in list_keys(sf)}
    assert _compose_environment(tmp_path, ["secrets.env"]) == ours
