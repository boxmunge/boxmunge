"""Tests for boxmunge.staging_data — staging data snapshot logic."""

import subprocess
from pathlib import Path
from unittest.mock import patch, call, MagicMock

import pytest
import yaml

from boxmunge.staging_data import (
    parse_volumes,
    copy_bind_mounts,
    copy_named_volumes,
    snapshot_prod_data,
)


class TestParseVolumes:
    def test_detects_bind_mounts(self) -> None:
        compose = {
            "services": {
                "web": {"volumes": ["./data:/app/data"]},
            },
        }
        bind, named = parse_volumes(compose)
        assert bind == [("./data", "./data-staging")]
        assert named == []

    def test_detects_named_volumes(self) -> None:
        compose = {
            "services": {
                "db": {"volumes": ["dbdata:/var/lib/postgresql/data"]},
            },
            "volumes": {"dbdata": None},
        }
        bind, named = parse_volumes(compose)
        assert bind == []
        assert named == ["dbdata"]

    def test_mixed_volumes(self) -> None:
        compose = {
            "services": {
                "app": {
                    "volumes": [
                        "./uploads:/app/uploads",
                        "cache:/app/cache",
                        "./logs:/app/logs:ro",
                    ],
                },
            },
            "volumes": {"cache": None},
        }
        bind, named = parse_volumes(compose)
        assert ("./uploads", "./uploads-staging") in bind
        assert ("./logs", "./logs-staging") in bind
        assert "cache" in named

    def test_no_volumes(self) -> None:
        compose = {"services": {"web": {"image": "nginx"}}}
        bind, named = parse_volumes(compose)
        assert bind == []
        assert named == []

    def test_deduplicates(self) -> None:
        compose = {
            "services": {
                "web": {"volumes": ["./data:/app/data"]},
                "worker": {"volumes": ["./data:/worker/data"]},
            },
        }
        bind, named = parse_volumes(compose)
        assert len(bind) == 1


class TestCopyBindMountsAbsolutePaths:
    @patch("boxmunge.staging_data._run_in_system_container")
    def test_absolute_path_in_project_tree(self, mock_run: MagicMock) -> None:
        bind_mounts = [
            ("/opt/boxmunge/projects/myapp/data",
             "/opt/boxmunge/projects/myapp/data-staging"),
        ]
        copy_bind_mounts(bind_mounts, "myapp")
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "/projects/myapp/data" in cmd
        assert "/projects/myapp/data-staging" in cmd

    def test_absolute_path_outside_project_tree_raises(self) -> None:
        bind_mounts = [("/var/lib/other", "/var/lib/other-staging")]
        with pytest.raises(ValueError, match="outside project tree"):
            copy_bind_mounts(bind_mounts, "myapp")


class TestCopyBindMounts:
    @patch("boxmunge.staging_data._run_in_system_container")
    def test_copies_via_system_container(self, mock_run: MagicMock) -> None:
        bind_mounts = [("./data", "./data-staging")]
        copy_bind_mounts(bind_mounts, "myapp")
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "cp" in cmd
        assert "/projects/myapp/data" in cmd
        assert "/projects/myapp/data-staging" in cmd

    @patch("boxmunge.staging_data._run_in_system_container")
    def test_multiple_bind_mounts(self, mock_run: MagicMock) -> None:
        bind_mounts = [
            ("./data", "./data-staging"),
            ("./uploads", "./uploads-staging"),
        ]
        copy_bind_mounts(bind_mounts, "myapp")
        assert mock_run.call_count == 2


class TestCopyNamedVolumes:
    @patch("boxmunge.staging_data._docker_run")
    def test_copies_via_busybox(self, mock_run: MagicMock) -> None:
        copy_named_volumes(["dbdata"], "myapp")
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "busybox" in cmd
        assert "myapp_dbdata" in " ".join(cmd)
        assert "myapp-staging_dbdata" in " ".join(cmd)

    @patch("boxmunge.staging_data._docker_run")
    def test_multiple_volumes(self, mock_run: MagicMock) -> None:
        copy_named_volumes(["dbdata", "cache"], "myapp")
        assert mock_run.call_count == 2


class TestSnapshotProdData:
    @patch("boxmunge.staging_data.copy_named_volumes")
    @patch("boxmunge.staging_data.copy_bind_mounts")
    @patch("boxmunge.staging_data.compose_start")
    @patch("boxmunge.staging_data.compose_stop")
    def test_full_flow(
        self, mock_stop: MagicMock, mock_start: MagicMock,
        mock_copy_bind: MagicMock, mock_copy_named: MagicMock,
        tmp_path: Path,
    ) -> None:
        compose_path = tmp_path / "compose.yml"
        compose_path.write_text(yaml.dump({
            "services": {
                "web": {"image": "nginx", "volumes": ["./data:/app/data"]},
                "db": {"image": "postgres", "volumes": ["dbdata:/pgdata"]},
            },
            "volumes": {"dbdata": None},
        }))

        snapshot_prod_data("myapp", tmp_path, compose_path)

        mock_stop.assert_called_once_with(
            tmp_path, compose_files=["compose.yml", "compose.boxmunge.yml"],
            project_name="myapp", timeout=15,
        )
        mock_copy_bind.assert_called_once()
        mock_copy_named.assert_called_once()
        mock_start.assert_called_once_with(
            tmp_path, compose_files=["compose.yml", "compose.boxmunge.yml"],
            project_name="myapp",
        )

        # Ordering is structurally guaranteed by the try/finally in snapshot_prod_data

    @patch("boxmunge.staging_data.copy_named_volumes")
    @patch("boxmunge.staging_data.copy_bind_mounts")
    @patch("boxmunge.staging_data.compose_start")
    @patch("boxmunge.staging_data.compose_stop")
    def test_prod_restarted_on_copy_failure(
        self, mock_stop: MagicMock, mock_start: MagicMock,
        mock_copy_bind: MagicMock, mock_copy_named: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Production must be restarted even if copying fails."""
        compose_path = tmp_path / "compose.yml"
        compose_path.write_text(yaml.dump({
            "services": {
                "web": {"image": "nginx", "volumes": ["./data:/app/data"]},
            },
        }))
        mock_copy_bind.side_effect = subprocess.CalledProcessError(1, "cp")

        with pytest.raises(subprocess.CalledProcessError):
            snapshot_prod_data("myapp", tmp_path, compose_path)

        # Even on failure, prod must be restarted
        mock_start.assert_called_once()
