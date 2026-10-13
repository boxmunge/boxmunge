"""Shared test fixtures for boxmunge CLI tests."""

import json
import os
import stat
import sys
from pathlib import Path

import pytest


@pytest.fixture
def tmp_project(tmp_path: Path) -> Path:
    """Create a temporary project directory."""
    return tmp_path / "myproject"


@pytest.fixture
def boxmunge_config(tmp_path: Path) -> Path:
    """Write a valid .boxmunge config and return the directory."""
    config = tmp_path / "myproject"
    config.mkdir()
    (config / ".boxmunge").write_text(
        "server: box.example.com\nport: 922\nuser: deploy\nproject: myapp\n"
    )
    return config


_FAKE_TOOL = """\
#!{python}
import json, os, sys
name = os.path.basename(sys.argv[0])
argv = sys.argv[1:]
with open(os.environ["FAKE_REMOTE_LOG"], "a") as log:
    log.write(json.dumps({{"prog": name, "argv": argv}}) + "\\n")
joined = " ".join([name] + argv)
with open(os.environ["FAKE_REMOTE_RULES"]) as f:
    rules = json.load(f)
for rule in rules:
    if rule["prog"] == name and rule["match"] in joined:
        sys.stdout.write(rule.get("stdout", ""))
        sys.stderr.write(rule.get("stderr", ""))
        sys.exit(rule.get("rc", 0))
sys.exit(0)
"""


class FakeRemote:
    """Fake ssh/scp/ssh-keyscan/cosign binaries on PATH that record their argv.

    Tests exercise the real subprocess calls; nothing in the client is
    mocked. `respond` adds a canned reply for invocations whose
    space-joined argv contains `match`.
    """

    TOOLS = ("ssh", "scp", "ssh-keyscan", "cosign")

    def __init__(self, bin_dir: Path, root: Path) -> None:
        self.bin = bin_dir
        self.log = root / "fake-remote.log"
        self.log.write_text("")
        self.rules_path = root / "fake-remote-rules.json"
        self._rules: list[dict] = []
        self._save()

    @classmethod
    def install_tools(cls, bin_dir: Path) -> None:
        bin_dir.mkdir()
        for tool in cls.TOOLS:
            path = bin_dir / tool
            path.write_text(_FAKE_TOOL.format(python=sys.executable))
            path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def _save(self) -> None:
        self.rules_path.write_text(json.dumps(self._rules))

    def respond(self, prog: str, match: str, stdout: str = "", stderr: str = "",
                rc: int = 0) -> None:
        self._rules.insert(0, {"prog": prog, "match": match, "stdout": stdout,
                               "stderr": stderr, "rc": rc})
        self._save()

    def calls(self, prog: str | None = None) -> list[list[str]]:
        entries = [json.loads(line) for line in self.log.read_text().splitlines()]
        return [e["argv"] for e in entries if prog is None or e["prog"] == prog]


HANDSHAKE_OK = json.dumps({
    "server_version": "0.11.0",
    "min_client_version": "0.1.0",
    "schema_version": 3,
})


@pytest.fixture(scope="session")
def _fake_bin(tmp_path_factory: pytest.TempPathFactory) -> Path:
    # Created once per session: on macOS the first exec of a new executable is
    # slow (it is scanned), so per-test copies would dominate the run time.
    bin_dir = tmp_path_factory.mktemp("fake-remote") / "bin"
    FakeRemote.install_tools(bin_dir)
    return bin_dir


@pytest.fixture
def fake_remote(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _fake_bin: Path) -> FakeRemote:
    fake = FakeRemote(_fake_bin, tmp_path)
    monkeypatch.setenv("PATH", str(fake.bin) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("FAKE_REMOTE_LOG", str(fake.log))
    monkeypatch.setenv("FAKE_REMOTE_RULES", str(fake.rules_path))
    fake.respond("ssh", "handshake", stdout=HANDSHAKE_OK)
    return fake
