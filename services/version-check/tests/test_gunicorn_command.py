"""The image's gunicorn command, checked against the gunicorn the lock installs."""

import json
import shlex
from pathlib import Path

from gunicorn.config import Config

SERVICE_DIR = Path(__file__).parent.parent


def _gunicorn_argv() -> list[str]:
    cmd = next(line for line in (SERVICE_DIR / "Dockerfile").read_text().splitlines()
               if line.startswith("CMD "))
    shell = json.loads(cmd[len("CMD "):])[2]
    return shlex.split(shell.split("exec gunicorn ", 1)[1])


def _parsed():
    # Config.parser() is the argparse gunicorn's CLI uses: an option this
    # gunicorn does not know exits here as it would in the container.
    return Config().parser().parse_args(_gunicorn_argv())


def test_the_control_socket_is_off():
    """gunicorn 25.1+ opens a control socket under $HOME/.gunicorn. The
    container's root filesystem is read-only, so it logged an ERROR on every
    start; on a writable one it is a control surface nobody uses."""
    assert _parsed().control_socket_disable is True


def test_the_command_still_binds_the_service_port_with_two_workers():
    args = _parsed()
    assert args.bind == ["0.0.0.0:8147"]
    assert args.workers == 2
    assert args.args == ["app:create_app()"]
