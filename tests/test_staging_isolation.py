# SPDX-License-Identifier: Apache-2.0
"""Overlap detection between production's and staging's resolved models.

The end-to-end check with real `docker compose config` is in
tests/integration/test_staging_isolation.py.
"""
from __future__ import annotations

from pathlib import Path

from boxmunge.staging_isolation import identities, overlaps


def _ids(tmp_path: Path, project: str, **svc) -> object:
    model = {"services": {"web": svc if "build" in svc else {"image": "x", **svc}},
             "networks": {"boxmunge-proxy": {"name": "boxmunge-proxy", "external": True}}}
    return identities(model, project, tmp_path)


def test_disjoint_defaults(tmp_path: Path) -> None:
    assert overlaps(_ids(tmp_path, "myapp", build="."),
                    _ids(tmp_path, "myapp-staging", build=".")) == []


def test_a_service_named_like_staging_collides(tmp_path: Path) -> None:
    """Production's service staging-web is named as staging's web would be."""
    prod = identities({"services": {"staging-web": {"build": "."}}}, "myapp", tmp_path)
    found = overlaps(prod, _ids(tmp_path, "myapp-staging", build="."))
    assert found == ["container name myapp-staging-web-1",
                     "image myapp-staging-web (staging builds it; production runs it)"]


def test_explicit_names_and_images_collide(tmp_path: Path) -> None:
    kw = {"container_name": "web", "build": ".", "image": "registry.example.com/app:1"}
    found = overlaps(_ids(tmp_path, "myapp", **kw), _ids(tmp_path, "myapp-staging", **kw))
    assert found == ["container name web",
                     "image registry.example.com/app:1 (staging builds it; production runs it)"]


def test_a_staging_build_never_retags_an_image_production_pulls(tmp_path: Path) -> None:
    prod = _ids(tmp_path, "myapp", image="myorg/app:latest")
    staging = identities({"services": {"web": {"build": ".", "image": "myorg/app:latest"}}},
                         "myapp-staging", tmp_path)
    assert overlaps(prod, staging) == [
        "image myorg/app:latest (staging builds it; production runs it)"]


def test_shared_aliases_on_the_proxy_network_collide(tmp_path: Path) -> None:
    nets = {"networks": {"boxmunge-proxy": {"aliases": ["shop"]}}}
    found = overlaps(_ids(tmp_path, "myapp", **nets), _ids(tmp_path, "myapp-staging", **nets))
    assert found == ["network alias boxmunge-proxy/shop"]


def test_bind_sources_collide_when_equal_or_nested(tmp_path: Path) -> None:
    def binds(*sources):
        return [{"type": "bind", "source": s, "target": f"/t{i}"} for i, s in enumerate(sources)]
    prod = _ids(tmp_path, "myapp", volumes=binds("./data", "./.releases/previous/conf"))
    staging = _ids(tmp_path, "myapp-staging",
                   volumes=binds("./data-staging", "./conf", f"{tmp_path}/data/sub"))
    found = overlaps(prod, staging)
    assert len(found) == 1 and f"{tmp_path}/data/sub" in found[0]
    assert "production web:/t0" in found[0]


def test_whole_project_mount_collides(tmp_path: Path) -> None:
    mount = {"volumes": [{"type": "bind", "source": ".", "target": "/app", "read_only": True}]}
    assert overlaps(_ids(tmp_path, "myapp", **mount), _ids(tmp_path, "myapp-staging", **mount))
