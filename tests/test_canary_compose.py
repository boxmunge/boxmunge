"""The canary keeps its data where a migration can carry it, as postgres."""
from pathlib import Path

import yaml

CANARY = Path(__file__).resolve().parents[1] / "canary" / "compose.yml"


def test_canary_db_keeps_its_data_in_a_named_volume_as_postgres() -> None:
    doc = yaml.safe_load(CANARY.read_text())
    db = doc["services"]["db"]
    assert db["user"] == "70:70"
    assert "pgdata:/var/lib/postgresql/data" in db["volumes"]
    assert doc["volumes"] == {"pgdata": {}}
