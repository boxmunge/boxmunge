# SPDX-License-Identifier: Apache-2.0
"""Per-project image pins: a service fixed to one image by digest.

Image tags are global to the Docker daemon (container_update_tags), so an
image one project must run, whatever its tag names later, is pinned per
project: `state/image_pins/<project>.json` holds {service, ref, digest,
reason} for each pinned service, and production's overlay
(compose.boxmunge.yml, compose.render_compose_override) emits
`image: <ref>@<digest>` for it. Every production start runs the overlay
(tests/test_image_pin_start_paths.py), so a pin holds across a restart,
resume, recover, restore, the health monitor's restart, a quarantine lift,
an upgrade and container update, which leaves a pinned service's image
alone.

A pin belongs to the release it was written for. A release switch (deploy,
promote, rollback) renders its release without the pins and clears them
once it records the switch (deploy_steps.record_deploy_state): the new
release ships its own images.

`reason` is "autofix" (a patched image, cve autofix). The Supply Chain
`manual` stance's pins will add their own reason here.

The record is deploy-writable state that root reads: through
fs_nofollow, and one it cannot use raises StateError.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Literal

from boxmunge.fileutil import atomic_write_text
from boxmunge.fs_nofollow import read_text_nofollow_or_none
from boxmunge.manifest import load_manifest
from boxmunge.release_txn import open_install_reason
from boxmunge.state import StateError

if TYPE_CHECKING:
    from collections.abc import Iterable

    from boxmunge.paths import BoxPaths

RECORD_VERSION = 1
REASONS = ("autofix",)
_FIELDS = ("service", "ref", "digest", "reason")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
# The component the overlay's render logs under when a pin write renders it.
_COMPONENT = "image-pins"


@dataclass(frozen=True)
class ImagePin:
    """`service` runs `ref@digest`. `ref` names the image without a digest
    (a tag may stay on it); `digest` is `sha256:<64 hex>`."""

    service: str
    ref: str
    digest: str
    reason: Literal["autofix"]

    def __post_init__(self) -> None:
        for field in _FIELDS:
            value = getattr(self, field)
            if not isinstance(value, str) or not value or value != value.strip() \
                    or any(c.isspace() for c in value):
                raise ValueError(f"image pin {field} must be a non-empty string without "
                                 f"spaces, got {value!r}")
        if "@" in self.ref:
            raise ValueError(f"image pin ref {self.ref!r} carries a digest; the digest is "
                             f"its own field")
        if not _DIGEST_RE.fullmatch(self.digest):
            raise ValueError(f"image pin digest {self.digest!r} is not sha256:<64 hex>")
        if self.reason not in REASONS:
            raise ValueError(f"image pin reason {self.reason!r} is not one of {REASONS}")

    @property
    def image(self) -> str:
        """The reference the overlay runs."""
        return f"{self.ref}@{self.digest}"


def read_pins(paths: BoxPaths, project: str) -> tuple[ImagePin, ...]:
    """The project's pins, by service; () when it has no record. Raises
    StateError, naming the file, for a record that cannot be read or used:
    a link or other non-regular file (refused, not followed), text that is
    not UTF-8 JSON, or a record not in the shape write_pins writes."""
    path = paths.project_image_pins(project)
    try:
        text = read_text_nofollow_or_none(path)
    except (OSError, UnicodeDecodeError) as e:
        raise StateError(f"cannot read {path}: {e}") from e
    if text is None:
        return ()
    try:
        return _parse(json.loads(text))
    except (ValueError, TypeError) as e:
        raise StateError(f"{path} is not an image pins record: {e}") from e


def _parse(doc: object) -> tuple[ImagePin, ...]:
    if not isinstance(doc, dict) or set(doc) != {"version", "pins"}:
        raise ValueError('expected {"version", "pins"}')
    if doc["version"] != RECORD_VERSION:
        raise ValueError(f"version {doc['version']!r}, expected {RECORD_VERSION}")
    entries = doc["pins"]
    if not isinstance(entries, list) or not entries:
        raise ValueError("pins must be a non-empty list")
    pins = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != set(_FIELDS):
            raise ValueError(f"each pin is exactly {{{', '.join(_FIELDS)}}}, got {entry!r}")
        pins.append(ImagePin(**entry))
    return _checked(pins)


def _checked(pins: Iterable[ImagePin]) -> tuple[ImagePin, ...]:
    """The pins by service. Raises ValueError for two pins of one service."""
    by_service: dict[str, ImagePin] = {}
    for pin in pins:
        if pin.service in by_service:
            raise ValueError(f"two pins for service {pin.service!r}")
        by_service[pin.service] = pin
    return tuple(by_service[svc] for svc in sorted(by_service))


def pinned_services(paths: BoxPaths, project: str) -> frozenset[str]:
    """The services a pin fixes. Raises StateError (read_pins)."""
    return frozenset(pin.service for pin in read_pins(paths, project))


def write_pins(paths: BoxPaths, project: str, pins: Iterable[ImagePin]) -> None:
    """Pin the project's services to `pins` (replacing every pin it had),
    then render production's overlay with them, which records the overlay's
    new hash in the bind record (compose.prepare_compose_override), so a
    start that renders nothing is not refused for it. Caller holds the
    project lock; nothing is started. Raises ValueError for no pins (use
    clear_pins), two for one service, or an open install (the project dir
    holds the release it installs, which the pins are not for), and what
    the render raises (a pin for a service the release lacks:
    ComposeError), the record written."""
    checked = _checked(pins)
    if not checked:
        raise ValueError("no pins to write; clear_pins removes a project's pins")
    install = open_install_reason(paths, project)
    if install is not None:
        raise ValueError(f"{project}'s image pins are not written while an install is "
                         f"open: {install}")
    path = paths.project_image_pins(project)
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, json.dumps({"version": RECORD_VERSION,
                                        "pins": [asdict(p) for p in checked]}, indent=2) + "\n")
    _render(paths, project)


def clear_pins(paths: BoxPaths, project: str) -> None:
    """Remove the project's pins and render production's overlay without
    them, as write_pins does. No record: nothing is touched. Caller holds
    the project lock. Raises what the render raises, the record removed."""
    path = paths.project_image_pins(project)
    if not os.path.lexists(path):
        return
    path.unlink()
    _render(paths, project)


def _render(paths: BoxPaths, project: str) -> None:
    # compose renders the overlay from read_pins, so it is imported here.
    from boxmunge.compose import prepare_compose_override
    prepare_compose_override(paths, load_manifest(paths.project_manifest(project)),
                             component=_COMPONENT)
