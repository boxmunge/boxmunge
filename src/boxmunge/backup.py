# SPDX-License-Identifier: Apache-2.0
"""Backup encryption, decryption, and pruning.

Uses the `age` CLI for encryption with an identity file (age-keygen key pair).
All backup archives are encrypted before writing to disk.

The backup key at /opt/boxmunge/config/backup.key must be an age identity file
(contains AGE-SECRET-KEY-1...). On first run after upgrade from passphrase mode,
run `boxmunge doctor` to migrate the key.
"""

import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

_BACKUP_CMD_TIMEOUT = 600  # 10 minutes for large database dumps


class BackupError(Exception):
    """Raised when a backup operation fails."""


def _run_cmd(cmd: list[str], timeout: int = _BACKUP_CMD_TIMEOUT, **kwargs) -> subprocess.CompletedProcess:
    """Run a command, raising BackupError on failure."""
    try:
        return subprocess.run(cmd, check=True, capture_output=True, text=True,
                              timeout=timeout, **kwargs)
    except subprocess.TimeoutExpired as e:
        raise BackupError(f"Command timed out after {timeout}s: {' '.join(cmd)}") from e
    except subprocess.CalledProcessError as e:
        raise BackupError(f"Command failed: {' '.join(cmd)}\n{e.stderr}") from e


def _run_age_cmd(cmd: list[str], timeout: int = _BACKUP_CMD_TIMEOUT) -> subprocess.CompletedProcess:
    """Run an age command, preferring the system container.

    Falls back to host-level execution if the system container isn't running.
    This allows the tool to work both on containerised servers and in
    development/test environments without Docker.
    """
    from boxmunge.system_container import system_exec, ensure_system_container, SystemContainerError

    if ensure_system_container():
        try:
            return system_exec(cmd, timeout=timeout)
        except SystemContainerError as e:
            raise BackupError(str(e)) from e

    # Fallback: run on host
    try:
        return subprocess.run(cmd, check=True, capture_output=True, text=True,
                              timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise BackupError(f"Command timed out after {timeout}s: {' '.join(cmd)}") from e
    except subprocess.CalledProcessError as e:
        raise BackupError(f"Command failed: {' '.join(cmd)}\n{e.stderr}") from e


def _container_path(host_path: Path) -> str:
    """Translate a host path to its container-internal equivalent.

    The system container mounts:
      /opt/boxmunge/config/backup.key → /config/backup.key
      /opt/boxmunge/projects/ → /projects/
    """
    path_str = str(host_path)
    if "/config/" in path_str:
        return "/config/" + host_path.name
    if "/projects/" in path_str:
        idx = path_str.index("/projects/")
        return path_str[idx:]
    raise ValueError(f"Cannot translate path to container path: {host_path}")


def _use_container() -> bool:
    """Check if the system container is available for age operations."""
    from boxmunge.system_container import ensure_system_container
    return ensure_system_container()


def _resolve_path(host_path: Path, use_container: bool) -> str:
    """Return container path if using container, host path otherwise."""
    if use_container:
        return _container_path(host_path)
    return str(host_path)


def _read_recipient(key_path: Path) -> str:
    """Extract the public key (recipient) from an age identity file."""
    for line in key_path.read_text().splitlines():
        if line.startswith("# public key: "):
            return line.removeprefix("# public key: ").strip()
    # If no comment header, derive it via age-keygen
    container = _use_container()
    result = _run_age_cmd(["age-keygen", "-y", _resolve_path(key_path, container)])
    return result.stdout.strip()


def backup_filename(project_name: str) -> str:
    """Generate a timestamped backup filename."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%S")
    return f"{project_name}-{ts}.tar.gz.age"


def encrypt_file(input_path: Path, output_path: Path, key_path: Path) -> None:
    """Encrypt a file using age, via system container if available.

    Writes to a temp file then renames to prevent partial encrypted files
    from appearing under the final name.
    """
    if not key_path.exists():
        raise FileNotFoundError(f"Backup encryption key not found: {key_path}")

    import tempfile as _tempfile
    fd, tmp_path_str = _tempfile.mkstemp(
        dir=output_path.parent, prefix=".encrypt-", suffix=".tmp"
    )
    os.close(fd)
    tmp_path = Path(tmp_path_str)

    try:
        recipient = _read_recipient(key_path)
        container = _use_container()
        _run_age_cmd([
            "age", "--encrypt", "-r", recipient,
            "-o", _resolve_path(tmp_path, container),
            _resolve_path(input_path, container),
        ])
        os.rename(tmp_path, output_path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def decrypt_file(input_path: Path, output_path: Path, key_path: Path) -> None:
    """Decrypt an age-encrypted file, via system container if available."""
    if not key_path.exists():
        raise FileNotFoundError(f"Backup encryption key not found: {key_path}")

    container = _use_container()
    _run_age_cmd([
        "age", "--decrypt", "-i", _resolve_path(key_path, container),
        "-o", _resolve_path(output_path, container),
        _resolve_path(input_path, container),
    ])


def prune_backups(
    backups_dir: Path, project_name: str, retention: int
) -> list[Path]:
    """Remove oldest backups beyond the retention count."""
    pattern = f"{project_name}-*.tar.gz.age"
    files = sorted(backups_dir.glob(pattern), key=lambda f: f.stat().st_mtime)

    to_prune = files[:-retention] if retention > 0 else files
    for f in to_prune:
        f.unlink()

    return to_prune
