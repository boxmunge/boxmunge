"""staging.copy_data's refusals say what went wrong and what to run."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from boxmunge.staging_copy_plan import CopyPlan, StagingDataError, Store
from boxmunge.staging_data import verify_plan


def _pair() -> CopyPlan:
    return CopyPlan(pairs=[(Store("volume", "pgdata", "myapp_pgdata"),
                            Store("volume", "pgdata", "myapp-staging_pgdata"))])


def test_a_missing_production_volume_names_prod_deploy() -> None:
    with patch("boxmunge.staging_data._volume_exists", return_value=False), \
            pytest.raises(StagingDataError) as e:
        verify_plan(_pair())
    message = str(e.value)
    assert "production volume myapp_pgdata (pgdata) does not exist" in message
    assert "deploy it with prod-deploy first, or remove staging.copy_data" in message


def test_a_missing_staging_volume_does_not_suggest_a_deploy() -> None:
    with patch("boxmunge.staging_data._volume_exists", side_effect=[True, False]), \
            pytest.raises(StagingDataError) as e:
        verify_plan(_pair())
    assert "staging volume" in str(e.value) and "prod-deploy" not in str(e.value)
