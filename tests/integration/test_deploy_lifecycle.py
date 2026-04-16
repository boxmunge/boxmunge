"""Integration tests for the deploy lifecycle."""

import json
import urllib.request

import pytest

from boxmunge.state import read_state


pytestmark = [pytest.mark.integration]


class TestDeployLifecycle:
    def test_deploy_starts_containers(self, deployed_fixture) -> None:
        """Deploy creates running containers reachable on the test port."""
        paths, project_name, port, compose_project = deployed_fixture
        resp = urllib.request.urlopen(f"http://localhost:{port}/healthz")
        assert resp.status == 200

    def test_healthcheck_returns_ok(self, deployed_fixture) -> None:
        """Healthcheck endpoint responds correctly."""
        paths, project_name, port, compose_project = deployed_fixture
        resp = urllib.request.urlopen(f"http://localhost:{port}/healthz")
        assert resp.read() == b"ok"

    def test_data_insert_and_read(self, deployed_fixture) -> None:
        """Can insert and read data through the running app."""
        paths, project_name, port, compose_project = deployed_fixture

        # Insert
        req = urllib.request.Request(
            f"http://localhost:{port}/data",
            data=b"integration-test-value",
            method="POST",
        )
        resp = urllib.request.urlopen(req)
        assert resp.status == 201

        # Read
        resp = urllib.request.urlopen(f"http://localhost:{port}/data")
        data = json.loads(resp.read())
        assert data["count"] >= 1

    def test_multiple_inserts_accumulate(self, deployed_fixture) -> None:
        """Multiple inserts increase the count."""
        paths, project_name, port, compose_project = deployed_fixture

        # Get baseline
        resp = urllib.request.urlopen(f"http://localhost:{port}/data")
        before = json.loads(resp.read())["count"]

        # Insert 3 rows
        for i in range(3):
            req = urllib.request.Request(
                f"http://localhost:{port}/data",
                data=f"row-{i}".encode(),
                method="POST",
            )
            urllib.request.urlopen(req)

        # Verify
        resp = urllib.request.urlopen(f"http://localhost:{port}/data")
        after = json.loads(resp.read())["count"]
        assert after == before + 3
