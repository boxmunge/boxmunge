"""Concurrent scp uploads through the deploy shell stay in their own session.

Each test drives the real /usr/bin/scp sink in separate processes, speaking
the scp protocol on stdin, so two uploads genuinely overlap on disk.
"""

import io
import os
import subprocess
import sys
import tarfile
import time
from pathlib import Path

import pytest

import boxmunge
from boxmunge.paths import BoxPaths

SCP = Path("/usr/bin/scp")

_SESSION = """
import sys
from pathlib import Path
import boxmunge.paths
real = boxmunge.paths.BoxPaths
boxmunge.paths.BoxPaths = lambda: real(Path(sys.argv[1]))
from boxmunge.shell import handle_scp_upload
handle_scp_upload(["-t", "."])
"""


def _bundle(project: str) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in (("manifest.yml", f"project: {project}\n".encode()),
                           ("payload.bin", os.urandom(64 * 1024))):
            info = tarfile.TarInfo(f"{project}/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class _Upload:
    """One deploy-shell scp session, fed the protocol by hand."""

    def __init__(self, root: Path, data: bytes, filename: str = "bundle.tar.gz"):
        self.data = data
        env = {**os.environ, "PYTHONPATH": str(Path(boxmunge.__file__).parents[1])}
        self.proc = subprocess.Popen(
            [sys.executable, "-c", _SESSION, str(root)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env,
        )
        self._send(f"C0644 {len(data)} {filename}\n".encode())

    def _send(self, chunk: bytes) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(chunk)
        self.proc.stdin.flush()

    def send_first_half(self) -> None:
        self._send(self.data[:len(self.data) // 2])

    def send_rest(self) -> None:
        self._send(self.data[len(self.data) // 2:] + b"\0")

    def finish(self) -> tuple[int, str]:
        _, err = self.proc.communicate(timeout=30)
        return self.proc.returncode, err.decode()

    def cancel(self) -> tuple[int, str]:
        """The client goes away mid-transfer: stdin closes before the file ends."""
        return self.finish()

    def terminate(self) -> int:
        self.proc.terminate()
        self.proc.communicate(timeout=30)
        return self.proc.returncode


def _wait_for_partial(paths: BoxPaths) -> tuple[Path, int]:
    """The one partly written upload under the temp area, and its size.

    scp writes in whole blocks, so the size on disk trails what was sent.
    """
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        found = [p for p in paths.inbox_tmp.rglob("*")
                 if p.is_file() and p.stat().st_size > 0] if paths.inbox_tmp.exists() else []
        if len(found) == 1:
            return found[0], found[0].stat().st_size
        time.sleep(0.05)
    raise AssertionError(f"no partial upload appeared under {paths.inbox_tmp}")


def _inbox_bundles(paths: BoxPaths, project: str) -> list[Path]:
    return sorted(paths.inbox.glob(f"{project}-*.tar.gz"))


@pytest.fixture
def paths(tmp_path: Path) -> BoxPaths:
    if not SCP.exists():
        pytest.fail(f"{SCP} is required: these tests drive the real scp sink")
    return BoxPaths(tmp_path)


def test_overlapping_uploads_with_the_same_filename_both_land(paths: BoxPaths) -> None:
    alpha, beta = _bundle("alpha"), _bundle("beta")
    first = _Upload(paths.root, alpha)
    first.send_first_half()
    partial, written = _wait_for_partial(paths)

    second = _Upload(paths.root, beta)
    second.send_first_half()
    second.send_rest()
    rc, err = second.finish()
    assert rc == 0, err
    [received_beta] = _inbox_bundles(paths, "beta")
    assert received_beta.read_bytes() == beta
    assert partial.stat().st_size == written, "the other session's partial upload was touched"

    first.send_rest()
    rc, err = first.finish()
    assert rc == 0, err
    [received_alpha] = _inbox_bundles(paths, "alpha")
    assert received_alpha.read_bytes() == alpha
    assert list(paths.inbox_tmp.iterdir()) == [], "a session left its temp directory behind"


def test_cancelled_upload_cleans_only_its_own_session(paths: BoxPaths) -> None:
    alpha, beta = _bundle("alpha"), _bundle("beta")
    first = _Upload(paths.root, alpha)
    first.send_first_half()
    partial, written = _wait_for_partial(paths)

    second = _Upload(paths.root, beta, filename="other.tar.gz")
    second.send_first_half()
    rc, _ = second.cancel()
    assert rc == 1
    assert partial.exists() and partial.stat().st_size == written
    assert _inbox_bundles(paths, "beta") == []
    assert len(list(paths.inbox_tmp.iterdir())) == 1, "the cancelled session left its directory"

    first.send_rest()
    rc, err = first.finish()
    assert rc == 0, err
    [received_alpha] = _inbox_bundles(paths, "alpha")
    assert received_alpha.read_bytes() == alpha


def test_terminated_upload_removes_its_partial_file(paths: BoxPaths) -> None:
    first = _Upload(paths.root, _bundle("alpha"))
    first.send_first_half()
    partial, written = _wait_for_partial(paths)

    second = _Upload(paths.root, _bundle("beta"))
    second.send_first_half()
    deadline = time.monotonic() + 15
    while len([p for p in paths.inbox_tmp.rglob("*") if p.is_file()]) < 2:
        assert time.monotonic() < deadline, "the second upload never started writing"
        time.sleep(0.05)
    assert second.terminate() != 0
    assert [p for p in paths.inbox_tmp.rglob("*") if p.is_file()] == [partial]
    assert partial.stat().st_size == written

    first.send_rest()
    rc, err = first.finish()
    assert rc == 0, err
