# SPDX-License-Identifier: Apache-2.0
"""The audit log: append-only JSON lines, fail-closed, secrets redacted."""
from __future__ import annotations

import json
import stat

import pytest

from boxmunge.api.audit import REDACTED, AuditError, AuditLog, audit_record, redact
from boxmunge.api.principal import Principal, Tier
from boxmunge.api.schema import STRING, arr, obj


def test_records_append_as_json_lines(tmp_path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    plugin = Principal.plugin("webui", Tier.OBSERVE)
    log.append(audit_record(plugin, "nope.nope", "refused", code="not_found", message="Unknown."))
    log.append(audit_record(Principal.operator(), "secrets.set", "accepted",
                            params={"project": "shop"}))
    lines = [json.loads(line) for line in log.path.read_text().splitlines()]
    assert [(r["principal"], r["action"], r["outcome"]) for r in lines] == [
        ("plugin:webui", "nope.nope", "refused"),
        ("operator:ssh", "secrets.set", "accepted"),
    ]
    assert lines[0]["params"] is None and lines[0]["code"] == "not_found"
    assert lines[1]["params"] == {"project": "shop"} and "code" not in lines[1]
    assert lines[0]["ts"].endswith("Z")


def test_new_log_is_mode_0640(tmp_path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append(audit_record(Principal.operator(), "a.b", "accepted"))
    assert stat.S_IMODE(log.path.stat().st_mode) == 0o640


def test_unwritable_log_raises(tmp_path) -> None:
    log = AuditLog(tmp_path / "missing-dir" / "audit.jsonl")
    with pytest.raises(AuditError, match="cannot append"):
        log.append(audit_record(Principal.operator(), "a.b", "accepted"))


def test_unknown_outcome_is_a_bug() -> None:
    with pytest.raises(ValueError, match="unknown audit outcome"):
        audit_record(Principal.operator(), "a.b", "maybe")


def test_secret_properties_are_redacted_at_every_depth() -> None:
    secret = {"type": "string", "secret": True}
    schema = obj({
        "project": STRING,
        "value": secret,
        "pairs": arr(obj({"key": STRING, "value": secret})),
    })
    params = {"project": "shop", "value": "hunter2",
              "pairs": [{"key": "A", "value": "x"}]}
    assert redact(schema, params) == {
        "project": "shop", "value": REDACTED,
        "pairs": [{"key": "A", "value": REDACTED}],
    }
