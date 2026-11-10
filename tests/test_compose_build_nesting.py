"""Build inputs may not lie inside a read-write bind source.

A bundle is validated in `.releases/incoming/`, where `./data` does not
exist yet. Once installed, a container that writes `./data` can replace
`data/ctx` with a symlink to `../../victim`; the next `compose build`
resolves the context root through it and bakes the victim's secrets.env
into an image that container then reads. So a build context, Dockerfile or
local additional context inside a read-write bind source is refused, like a
nested bind or a secrets file there, judged on the declared paths rather
than on what the filesystem holds at validation.
"""
from __future__ import annotations

from typing import Any

import pytest
import yaml

from boxmunge.compose_validate import ComposeSecurityError, validate_user_compose
from boxmunge.paths import BoxPaths

_RW_DATA = {"volumes": ["./data:/data"]}


def _validate_bundle(paths: BoxPaths, svc: dict[str, Any]) -> None:
    """Validate the way intake does: from an extraction directory under
    `.releases/incoming/` that holds no `./data`."""
    incoming = paths.project_dir("myapp") / ".releases" / "incoming" / "r1"
    incoming.mkdir(parents=True)
    compose = incoming / "compose.yml"
    compose.write_text(yaml.safe_dump({"services": {"web": svc}}))
    assert not (incoming / "data").exists()
    validate_user_compose(compose, paths, project_name="myapp")


REFUSED = {
    "context inside rw bind": {"build": "./data/ctx"},
    "context mapping inside rw bind": {"build": {"context": "./data/ctx"}},
    "dockerfile inside rw bind": {"build": {"context": ".", "dockerfile": "data/Dockerfile"}},
    # `build: ./app` + `./app:/app` read-write. The context root itself
    # cannot be swapped and BuildKit sends links inside it as links, but the
    # Dockerfile is the container's to write (a release may not ship content
    # for a read-write mount, release._check): `COPY --from=` another
    # project's image, never scanned, reads that image into this one; and a
    # `dockerfile:` subdirectory swapped for a link is followed.
    "context is the rw bind (./app layout)": {"build": "./data"},
    "dockerfile directory is the rw bind": {
        "build": {"context": "./data", "dockerfile": "Dockerfile"}},
    "additional context inside rw bind": {
        "build": {"context": ".", "additional_contexts": {"x": "./data/extra"}}},
    "additional context list form": {
        "build": {"context": ".", "additional_contexts": ["x=./data/extra"]}},
}


@pytest.mark.parametrize("build", REFUSED.values(), ids=REFUSED.keys())
def test_build_input_inside_rw_bind_refused(paths: BoxPaths, build: dict) -> None:
    with pytest.raises(ComposeSecurityError, match="lies inside"):
        _validate_bundle(paths, {**build, **_RW_DATA})


def test_build_input_inside_another_services_rw_bind_refused(paths: BoxPaths) -> None:
    incoming = paths.project_dir("myapp") / ".releases" / "incoming" / "r1"
    incoming.mkdir(parents=True)
    compose = incoming / "compose.yml"
    compose.write_text(yaml.safe_dump({"services": {
        "web": {"build": "./data/ctx"},
        "db": {"image": "postgres:16", **_RW_DATA},
    }}))
    with pytest.raises(ComposeSecurityError, match="service web: build context"):
        validate_user_compose(compose, paths, project_name="myapp")


ACCEPTED = {
    "context beside rw bind": {"build": "./web"},
    "project root context": {"build": "."},
    "remote context": {"build": "https://example.com/app.git#main"},
    "service additional context": {
        "build": {"context": "./web", "additional_contexts": {"x": "service:db"}}},
}


@pytest.mark.parametrize("build", ACCEPTED.values(), ids=ACCEPTED.keys())
def test_build_input_beside_rw_bind_accepted(paths: BoxPaths, build: dict) -> None:
    _validate_bundle(paths, {**build, **_RW_DATA})


def test_build_input_inside_read_only_bind_accepted(paths: BoxPaths) -> None:
    _validate_bundle(paths, {"build": "./data/ctx", "volumes": ["./data:/data:ro"]})
