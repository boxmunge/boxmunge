"""Integration test — end-to-end stage workflow with mocked SSH."""

import json
import yaml
from pathlib import Path
from unittest.mock import patch, MagicMock

from boxmunge_cli.config import load_config


def _setup_project(tmp_path: Path) -> Path:
    """Create a complete project with .boxmunge and valid manifest."""
    project = tmp_path / "myapp"
    project.mkdir()
    (project / ".boxmunge").write_text(yaml.dump({
        "server": "box.example.com",
        "port": 922,
        "user": "deploy",
        "project": "myapp",
    }, sort_keys=False))
    (project / "manifest.yml").write_text(yaml.dump({
        "id": "01TESTULID0000000000000000",
        "project": "myapp",
        "source": "bundle",
        "hosts": ["myapp.example.com"],
        "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        "backup": {"type": "none"},
    }, sort_keys=False))
    (project / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
    return project


def _make_subprocess_side_effect(handshake_stdout: str):
    """Return a side_effect function: handshake calls return JSON; others return 0."""
    def side_effect(cmd, **kwargs):
        if cmd[-1] == "handshake":
            return MagicMock(returncode=0, stdout=handshake_stdout)
        return MagicMock(returncode=0)
    return side_effect


class TestEndToEndStage:
    @patch("subprocess.run")
    def test_stage_bundles_handshakes_uploads_triggers(
        self, mock_run, tmp_path
    ):
        """Verify the full stage workflow: bundle → handshake → upload → trigger."""
        project = _setup_project(tmp_path)

        handshake_response = json.dumps({
            "server_version": "0.2.0",
            "min_client_version": "0.1.0",
            "schema_version": 1,
        })
        mock_run.side_effect = _make_subprocess_side_effect(handshake_response)

        config = load_config(project / ".boxmunge")

        from boxmunge_cli.bundle_cmd import run_bundle
        from boxmunge_cli.handshake import check_server_compatibility
        from boxmunge_cli.ssh import run_scp, run_ssh
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            exit_code = run_bundle(str(project), output=tmpdir)
            assert exit_code == 0

            bundles = list(Path(tmpdir).glob("*.tar.gz"))
            assert len(bundles) == 1
            bundle_path = str(bundles[0])

            check_server_compatibility(config)

            scp_code = run_scp(config, bundle_path)
            assert scp_code == 0

            ssh_code = run_ssh(config, "stage", "myapp")
            assert ssh_code == 0

        # Verify SCP was called with the bundle
        scp_calls = [c for c in mock_run.call_args_list
                     if c[0][0][0] == "scp"]
        assert len(scp_calls) == 1
        # Find the bundle filename arg (after scp, -P, port, -o, StrictHostKeyChecking...)
        scp_args = scp_calls[0][0][0]
        bundle_arg = [a for a in scp_args if "myapp-" in a]
        assert bundle_arg, f"No bundle filename in SCP args: {scp_args}"

        # Verify SSH trigger was called
        ssh_calls = [c for c in mock_run.call_args_list
                     if c[0][0][0] == "ssh" and c[0][0][-2] == "stage"]
        assert len(ssh_calls) == 1
        assert ssh_calls[0][0][0] == [
            "ssh", "-p", "922", "-o", "StrictHostKeyChecking=accept-new",
            "deploy@box.example.com", "stage", "myapp"
        ]
