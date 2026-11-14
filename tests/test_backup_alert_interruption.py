"""An interrupted backup alert is sent again; a delivered one is not."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from boxmunge import backup_evidence
from boxmunge.backup_alerts import deliver
from boxmunge.backup_evidence import PENDING_LEASE, project_evidence, record_failure
from tests.backup_alert_helpers import Alerts, backed_up_project, no_space
from tests.fake_system_container import fake_age

P = "shop"
T0 = datetime(2026, 11, 1, 2, 0, tzinfo=timezone.utc)


@pytest.fixture
def project(paths, system_container):
    system_container.handler = fake_age(paths)
    return backed_up_project(paths, P)


class Interrupted(BaseException):
    """The process dies at the delivery boundary (not an Exception)."""


def _die(*a, **k):
    raise Interrupted


def test_an_alert_interrupted_before_delivery_is_sent_by_the_next_run(paths, project) -> None:
    record_failure(paths, P, "dump failed", now=T0)
    with pytest.raises(Interrupted):
        deliver(paths, _die, now=T0)
    ev = project_evidence(paths, P)
    assert ev.alerted == {} and ev.pending == {"failing": T0.isoformat()}

    working = Alerts()
    deliver(paths, working, now=T0 + timedelta(minutes=5))   # inside the lease: still live
    assert working.sent == []
    deliver(paths, working, now=T0 + PENDING_LEASE + timedelta(minutes=5))   # a fresh process
    assert [t for t, _ in working.titles] == ["shop: scheduled backup failed"]
    ev = project_evidence(paths, P)
    assert ev.alerted == {"failing": T0.isoformat()} and ev.pending == {}
    deliver(paths, working, now=T0 + PENDING_LEASE + timedelta(minutes=10))
    assert len(working.sent) == 1


def test_an_alert_interrupted_after_delivery_is_sent_again_not_lost(
        paths, project, monkeypatch) -> None:
    record_failure(paths, P, "dump failed", now=T0)
    first = Alerts()
    monkeypatch.setattr("boxmunge.backup_alerts.mark_delivered", _die)
    with pytest.raises(Interrupted):
        deliver(paths, first, now=T0)
    monkeypatch.undo()
    again = Alerts()
    deliver(paths, again, now=T0 + PENDING_LEASE + timedelta(minutes=5))
    assert len(first.sent) == 1 and len(again.sent) == 1   # a bounded duplicate
    deliver(paths, again, now=T0 + PENDING_LEASE + timedelta(minutes=10))
    assert len(again.sent) == 1


def test_a_delivery_that_cannot_be_recorded_is_sent_again(paths, project, monkeypatch) -> None:
    record_failure(paths, P, "dump failed", now=T0)
    alerts = Alerts()
    real = backup_evidence.mark_delivered
    monkeypatch.setattr("boxmunge.backup_alerts.mark_delivered", no_space)
    deliver(paths, alerts, now=T0)
    assert project_evidence(paths, P).alerted == {}
    monkeypatch.setattr("boxmunge.backup_alerts.mark_delivered", real)
    deliver(paths, alerts, now=T0 + PENDING_LEASE + timedelta(minutes=5))
    assert len(alerts.sent) == 2
    assert project_evidence(paths, P).alerted == {"failing": T0.isoformat()}


def test_a_delivery_that_keeps_failing_to_record_is_resent_once_per_lease(
        paths, project, monkeypatch) -> None:
    record_failure(paths, P, "dump failed", now=T0)
    alerts = Alerts()
    monkeypatch.setattr("boxmunge.backup_alerts.mark_delivered", no_space)
    for tick in range(24):                       # two hours of five-minute ticks
        deliver(paths, alerts, now=T0 + timedelta(minutes=5 * tick))
    assert len(alerts.sent) == 2                 # at T0 and once the lease ended


def test_a_refused_alert_is_retried_on_the_next_tick(paths, project) -> None:
    record_failure(paths, P, "dump failed", now=T0)
    alerts = Alerts()
    alerts.delivers = False
    deliver(paths, alerts, now=T0)
    deliver(paths, alerts, now=T0 + timedelta(minutes=5))
    assert len(alerts.sent) == 2 and project_evidence(paths, P).pending == {}
