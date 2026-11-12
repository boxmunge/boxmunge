"""The upgrade shim's own alerts are sent from a box whose boxmunge.yml
holds a wrong setting.

During the hop the shim of the release being left is still in memory, and
sends "upgrade applied" and the alert before a rollback through the new
release's python, calling load_config(BoxPaths()) the only way it knows.
The real notify_via of each kept shim, and of this release's, runs here
against the real package and a real config; only the Pushover POST is
caught.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

import boxmunge

REPO = Path(__file__).resolve().parent.parent
OLD_SHIMS = sorted((REPO / "tests" / "integration" / "old_shims").glob("boxmunge-upgrade-v*"))
SHIMS = [REPO / "scripts" / "boxmunge-upgrade.d" / "slots.sh",
         *(shim for shim in OLD_SHIMS if "notify_via() {" in shim.read_text())]

CONFIG = {
    "hostname": "box.example.com", "admin_email": "ops@example.com",
    "pushover": {"user_key": "u", "app_token": "t"},
}
ODD = {**CONFIG, "logging": {"docker_max_file": "5"}, "reboot": {"auto_reboot": "yes"},
       "ssh_port": "922", "health": {"alert_threshold": "3"}}

# The shim's `-c <code>`, run with BoxPaths() pointed at the test's root
# and the POST printed instead of made.
WRAPPER = '''
import json, os, sys
from pathlib import Path
import boxmunge.pushover as pushover
from boxmunge.paths import BoxPaths
BoxPaths.__init__.__defaults__ = (Path(os.environ["BOXMUNGE_TEST_ROOT"]),)
def post(data):
    print(json.dumps({"title": data["title"], "message": data["message"]}))
    return True
pushover._post_pushover = post
exec(sys.argv[1])
'''


def _notify_via(tmp_path: Path, shim: Path, config: dict) -> subprocess.CompletedProcess:
    root = tmp_path / "bm"
    (root / "config").mkdir(parents=True)
    (root / "config" / "boxmunge.yml").write_text(yaml.safe_dump(config))
    (tmp_path / "wrapper.py").write_text(WRAPPER)
    python = tmp_path / "python"
    python.write_text(
        "#!/bin/sh\n[ \"$1\" = -c ] || exit 64\n"
        f"PYTHONPATH={Path(boxmunge.__file__).parent.parent} BOXMUNGE_TEST_ROOT={root} "
        f"exec {sys.executable} {tmp_path / 'wrapper.py'} \"$2\"\n")
    python.chmod(0o755)
    return subprocess.run(
        ["bash", "-c", f"""eval "$(sed -n '/^notify_via() {{$/,/^}}$/p' "{shim}")"
notify_via "{python}" "boxmunge upgrade applied" "Updated to 9.9.9" 1"""],
        capture_output=True, text=True)


def test_an_older_shim_is_among_those_run() -> None:
    assert len(SHIMS) > 1


@pytest.mark.parametrize("shim", SHIMS, ids=[s.name for s in SHIMS])
@pytest.mark.parametrize("config", [CONFIG, ODD], ids=["a sound config", "wrong settings"])
def test_the_alert_is_sent(tmp_path: Path, shim: Path, config: dict) -> None:
    result = _notify_via(tmp_path, shim, config)
    assert result.returncode == 0, result.stderr
    sent = json.loads(result.stdout)
    assert sent["title"].endswith("boxmunge upgrade applied")
    assert sent["message"] == "Updated to 9.9.9"


@pytest.mark.parametrize("shim", SHIMS, ids=[s.name for s in SHIMS])
def test_no_pushover_is_still_exit_3(tmp_path: Path, shim: Path) -> None:
    result = _notify_via(tmp_path, shim, {**ODD, "pushover": {}})
    assert (result.returncode, result.stdout) == (3, "")
