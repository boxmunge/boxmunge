"""While an install transaction is open, only the core resuming it starts production."""
from __future__ import annotations

from unittest.mock import patch

import pytest
import yaml

from boxmunge.compose_guard import ComposeRefused, compose_up_checked
from boxmunge.release import mark_live
from boxmunge.release_txn import open_txn, refuse_if_install_open
from tests.deploy_helpers import mark_deployed

P = "shop"
FILES = ["compose.yml"]


@pytest.fixture
def project(paths):
    paths.config_file.parent.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text(yaml.safe_dump({   # alerts need a Pushover config
        "hostname": "box.example.com", "admin_email": "ops@example.com",
        "pushover": {"user_key": "u", "app_token": "t"}}))
    pdir = paths.project_dir(P)
    pdir.mkdir(parents=True)
    (pdir / "manifest.yml").write_text(yaml.safe_dump({
        "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ", "project": P, "source": "bundle",
        "hosts": [f"{P}.example.com"], "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
    }))
    (pdir / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
    mark_deployed(paths, P)
    mark_live(paths, P, "shop-v1")
    return pdir


def _txn(paths):
    return open_txn(paths, P, source="bundle", ref="shop-v2", replaced_ref="shop-v1",
                    staged_id=None, snapshot="")


def test_production_start_refused_while_an_install_is_open(paths, project) -> None:
    _txn(paths)
    sent: list[str] = []
    with patch("boxmunge.compose_guard.compose_up") as up, \
            patch("boxmunge.notify.send_notification",
                  lambda u, t, title, body, priority=0: sent.append(body) or True), \
            pytest.raises(ComposeRefused, match="shop-v2"):
        compose_up_checked(paths, P, component="upgrade", compose_files=FILES)
    up.assert_not_called()
    assert "prod-deploy shop --abandon" in sent[0]
    assert "tampered" not in sent[0]


def test_the_resuming_core_passes_its_token(paths, project) -> None:
    txn = _txn(paths)
    with patch("boxmunge.compose_guard.compose_up") as up:
        compose_up_checked(paths, P, component="deploy", compose_files=FILES, txn=txn.id,
                           record=True, deploying=True)
    up.assert_called_once()


def test_a_wrong_token_is_refused(paths, project) -> None:
    _txn(paths)
    with patch("boxmunge.compose_guard.compose_up"), pytest.raises(ComposeRefused):
        compose_up_checked(paths, P, component="deploy", compose_files=FILES, txn="01OTHER")


def test_alerted_once_per_transaction(paths, project) -> None:
    _txn(paths)
    sent: list[str] = []
    with patch("boxmunge.compose_guard.compose_up"), \
            patch("boxmunge.notify.send_notification",
                  lambda u, t, title, body, priority=0: sent.append(title) or True):
        for _ in range(3):
            with pytest.raises(ComposeRefused):
                compose_up_checked(paths, P, component="check-all", compose_files=FILES)
    assert len(sent) == 1


def test_stale_transaction_names_install_txn_drop(paths, project) -> None:
    _txn(paths)
    mark_live(paths, P, "shop-v9")
    with patch("boxmunge.compose_guard.compose_up"), \
            pytest.raises(ComposeRefused, match="install-txn shop --drop"):
        compose_up_checked(paths, P, component="resume", compose_files=FILES)


def test_refuse_if_install_open(paths, project, capsys) -> None:
    assert refuse_if_install_open(paths, P, component="restore") is False
    txn = _txn(paths)
    assert refuse_if_install_open(paths, P, component="restore") is True
    assert "shop-v2" in capsys.readouterr().err
    assert refuse_if_install_open(paths, P, component="restore", txn=txn.id) is False


def test_restarting_stopped_containers_refused_while_an_install_is_open(paths, project) -> None:
    """`docker start` of production's containers is a production start too."""
    from boxmunge.compose_guard import start_containers_checked
    _txn(paths)
    with patch("boxmunge.compose_guard.start_containers") as start, \
            pytest.raises(ComposeRefused, match="shop-v2"):
        start_containers_checked(paths, P, ["shop-web-1"], component="stage")
    start.assert_not_called()
