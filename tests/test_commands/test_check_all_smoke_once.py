"""T6: the mutating check-all runs a project's smoke once per tick and
records the failure that decided its status. It used to run smoke again
only to fetch the alert text: the second run could pass, so a critical
stop (or a warning) was recorded with an empty reason."""
from __future__ import annotations

from unittest.mock import patch

from boxmunge.commands import check, check_all
from boxmunge.commands.smoke_result import SmokeResult
from tests.test_legacy_stage_undetermined import _deployed


def _with_smoke(paths) -> None:
    _deployed(paths)
    manifest = paths.project_manifest("myapp")
    manifest.write_text(manifest.read_text().replace(
        "    port: 8080\n", "    port: 8080\n    smoke: smoke.sh\n", 1))


def test_one_smoke_run_and_its_message_is_recorded(paths) -> None:
    _with_smoke(paths)
    results = [SmokeResult(status="critical", message="db unreachable"),
               SmokeResult(status="ok", message="")]
    with patch.object(check, "run_smoke_in_container", side_effect=results) as smoke, \
            patch.object(check_all, "update_health_state") as health:
        assert check_all._check_one("myapp", paths, read_only=False) == 2
    assert smoke.call_count == 1
    assert health.call_args.args[:3] == ("myapp", 2, "db unreachable")


def test_a_pass_records_no_message(paths) -> None:
    _with_smoke(paths)
    with patch.object(check, "run_smoke_in_container",
                      return_value=SmokeResult(status="ok", message="")), \
            patch.object(check_all, "update_health_state") as health:
        assert check_all._check_one("myapp", paths, read_only=False) == 0
    assert health.call_args.args[:3] == ("myapp", 0, "")
