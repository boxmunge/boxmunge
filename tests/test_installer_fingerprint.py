# SPDX-License-Identifier: Apache-2.0
"""install.sh records, and the upgrade shim recomputes over a new bundle, one
fingerprint covering install.sh and the files it installs from, so a release
that changes only bootstrap/ or the sshd drop-in still re-runs install.sh."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
# The part after `cd "<bundle>" && `, up to the end of the pipeline.
_EXPR = re.compile(r'cd "[^"]+" && (find \. .*?awk \'\{print \$1\}\')')


def _expr(path: Path) -> str:
    found = _EXPR.findall(path.read_text())
    assert len(found) == 1, path
    return found[0]


def test_install_sh_and_the_shim_compute_the_same_fingerprint() -> None:
    assert _expr(REPO / "install.sh") == _expr(REPO / "scripts" / "boxmunge-upgrade")


def _bundle(root: Path) -> Path:
    for rel in ("install.sh", "bootstrap/sshd-hardening.sh",
                "src/boxmunge/sshd/00-boxmunge.conf", "src/boxmunge/shell.py"):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(f"{rel}\n")
    return root


def _fingerprint(bundle: Path, tmp: Path) -> str:
    # sha256sum is coreutils (Linux); a stand-in with its output format keeps
    # the real pipeline runnable on any test host.
    bin_dir = tmp / "bin"
    if shutil.which("sha256sum") is None and not bin_dir.exists():
        bin_dir.mkdir()
        stub = bin_dir / "sha256sum"
        stub.write_text(
            f"#!{sys.executable}\nimport hashlib, sys\n"
            "for p in sys.argv[1:] or ['-']:\n"
            "    data = sys.stdin.buffer.read() if p == '-' else open(p, 'rb').read()\n"
            "    print(f'{hashlib.sha256(data).hexdigest()}  {p}')\n")
        stub.chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}
    script = f'( cd "{bundle}" && {_expr(REPO / "install.sh")}'
    out = subprocess.run(["bash", "-o", "pipefail", "-c", script], env=env,
                         capture_output=True, text=True, check=True).stdout.strip()
    assert re.fullmatch(r"[0-9a-f]{64}", out), out
    return out


def test_a_change_to_any_installed_from_file_changes_the_fingerprint(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path / "bundle")
    base = _fingerprint(bundle, tmp_path)
    assert _fingerprint(bundle, tmp_path) == base
    for rel in ("install.sh", "bootstrap/sshd-hardening.sh", "src/boxmunge/sshd/00-boxmunge.conf"):
        path = bundle / rel
        original = path.read_text()
        path.write_text(original + "changed\n")
        assert _fingerprint(bundle, tmp_path) != base, rel
        path.write_text(original)
    (bundle / "src/boxmunge/shell.py").write_text("python changes alone do not re-run it\n")
    assert _fingerprint(bundle, tmp_path) == base
