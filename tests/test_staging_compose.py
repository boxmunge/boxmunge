# SPDX-License-Identifier: Apache-2.0
"""The staging compose base names nothing production uses."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from boxmunge.compose import ComposeError
from boxmunge.staging_compose import generate_staging_compose_base

DATA = {"data", "uploads", "secrets.env"}


def _base(tmp_path: Path, doc: object, box_state: set[str] = DATA) -> dict:
    compose = tmp_path / "compose.yml"
    compose.write_text(doc if isinstance(doc, str) else yaml.safe_dump(doc))
    return yaml.safe_load(generate_staging_compose_base(compose, box_state, tmp_path))


def _volumes(tmp_path: Path, *entries: object) -> list:
    doc = {"services": {"web": {"image": "nginx", "volumes": list(entries)}}}
    return _base(tmp_path, doc)["services"]["web"]["volumes"]


def test_data_mounts_move_to_the_entrys_staging_copy(tmp_path: Path) -> None:
    assert _volumes(tmp_path, "./data:/app/data", "./uploads/img:/img:ro", "./data/db/:/db") == [
        f"{tmp_path}/data-staging:/app/data", f"{tmp_path}/uploads-staging/img:/img:ro",
        f"{tmp_path}/data-staging/db:/db"]


def test_release_code_mounts_keep_the_staged_release(tmp_path: Path) -> None:
    """Release code stays relative: it resolves inside the staged release."""
    assert _volumes(tmp_path, "./appconfig:/etc/app:ro", "./nginx.conf:/etc/n.conf:ro") == [
        "./appconfig:/etc/app:ro", "./nginx.conf:/etc/n.conf:ro"]


def test_absolute_sources(tmp_path: Path) -> None:
    inside = f"{tmp_path}/data/db:/db"
    assert _volumes(tmp_path, inside, "/srv/shared:/shared") == [
        f"{tmp_path}/data-staging/db:/db", "/srv/shared-staging:/shared"]


def test_long_syntax_and_volumes(tmp_path: Path) -> None:
    vols = _volumes(tmp_path,
                    {"type": "bind", "source": "./data", "target": "/data"},
                    {"type": "volume", "source": "cache", "target": "/cache"},
                    "dbdata:/var/lib/db", "/anon")
    assert vols[0]["source"] == f"{tmp_path}/data-staging"
    assert vols[1]["source"] == "cache"
    assert vols[2:] == ["dbdata:/var/lib/db", "/anon"]


def test_explicit_names_and_ports_are_dropped(tmp_path: Path) -> None:
    base = _base(tmp_path, {
        "services": {"web": {"image": "nginx",
                             "ports": ["8080:80"], "networks": ["internal"]}},
        "volumes": {"data": {"name": "myapp_data"}},
        "networks": {"internal": {"name": "myapp_internal"}},
    })
    assert base["services"]["web"] == {"image": "nginx", "networks": ["internal"]}
    assert base["volumes"] == {"data": {}}
    assert base["networks"] == {"internal": {}}


def test_external_resources_are_refused(tmp_path: Path) -> None:
    with pytest.raises(ComposeError, match="external"):
        _base(tmp_path, {"services": {"web": {"image": "x"}},
                         "volumes": {"data": {"external": True}}})


@pytest.mark.parametrize("doc", [
    {"include": ["parts/db.yml"], "services": {"web": {"image": "x"}}},
    {"services": {"web": {"extends": {"file": "base.yml", "service": "app"}}}},
], ids=["include", "extends file"])
def test_services_from_other_files_are_refused(tmp_path: Path, doc: dict) -> None:
    with pytest.raises(ComposeError, match="Move those services into compose.yml"):
        _base(tmp_path, doc)


@pytest.mark.parametrize("text,match", [
    ("services:\n  - web\n", "services"), ("just a string\n", "mapping")])
def test_malformed_compose_is_refused(tmp_path: Path, text: str, match: str) -> None:
    with pytest.raises(ComposeError, match=match):
        _base(tmp_path, text)


def test_config_and_secret_files_in_box_state_use_staging_copies(tmp_path: Path) -> None:
    base = _base(tmp_path, {
        "services": {"web": {"image": "x"}},
        "configs": {"app": {"file": "./conf/app.conf"}, "tls": {"file": "./data/tls.pem"}},
        "secrets": {"env": {"file": "./secrets.env"}},
    })
    assert base["configs"] == {"app": {"file": "./conf/app.conf"},
                               "tls": {"file": f"{tmp_path}/data-staging/tls.pem"}}
    assert base["secrets"] == {"env": {"file": f"{tmp_path}/secrets.env-staging"}}
