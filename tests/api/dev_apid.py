# SPDX-License-Identifier: Apache-2.0
"""A dev-mode boxmunge-apid subprocess that cannot outlive its test."""
from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
STOP_TIMEOUT = 10


class DevApid:
    """Own session (so the whole process group can be killed) plus a stdin pipe
    with --exit-on-stdin-eof (so the server stops even if we are SIGKILLed)."""

    def __init__(self, root: Path, sock_path: Path, plugin: str = "webui") -> None:
        self.root, self.sock_path, self.plugin = root, sock_path, plugin
        self.proc: subprocess.Popen[bytes] | None = None
        self.stderr = ""

    def start(self) -> "DevApid":
        env = {**os.environ, "PYTHONPATH": str(REPO / "src")}
        apid = [sys.executable, "-m", "boxmunge.api.apid"]
        if not self.root.exists():  # tests that start many servers share one fixture
            made = subprocess.run([*apid, "--make-fixture", str(self.root)], env=env,
                                  capture_output=True)
            if made.returncode:
                raise AssertionError(f"--make-fixture failed: {made.stderr.decode()}")
        self.proc = subprocess.Popen(
            [*apid, "--dev", "--root", str(self.root), "--socket", str(self.sock_path),
             "--plugin", self.plugin, "--exit-on-stdin-eof"],
            env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True)
        try:
            self._wait_for_socket()
        except BaseException:
            self.stop()
            raise
        return self

    def _wait_for_socket(self) -> None:
        for _ in range(200):
            if self.proc.poll() is not None:
                raise AssertionError(f"apid exited early: {self.proc.stderr.read().decode()}")
            if self.sock_path.exists():
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                    try:
                        probe.connect(str(self.sock_path))
                        return
                    except ConnectionRefusedError:
                        pass
            time.sleep(0.05)
        raise AssertionError("apid did not start listening")

    def stop(self) -> None:
        """SIGTERM the server's group, wait, and SIGKILL the group before reaping
        if it will not go (killing after the reap could hit a recycled pgid)."""
        if self.proc is None:
            return
        if self.proc.poll() is None:
            os.killpg(self.proc.pid, signal.SIGTERM)
        try:
            _, err = self.proc.communicate(timeout=STOP_TIMEOUT)
        except subprocess.TimeoutExpired:
            os.killpg(self.proc.pid, signal.SIGKILL)
            self.proc.communicate()
            raise AssertionError(f"apid ignored SIGTERM for {STOP_TIMEOUT}s")
        self.stderr = err.decode()

    @property
    def returncode(self) -> int | None:
        return self.proc.returncode

    def __enter__(self) -> "DevApid":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()
