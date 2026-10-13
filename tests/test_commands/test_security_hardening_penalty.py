# SPDX-License-Identifier: Apache-2.0
"""The CVE hardening penalty follows what the overlay actually applies.

The overlay hardens compose-only (undeclared) services with
no-new-privileges, init, a pids limit and cap drops, but NOT a read-only
root filesystem: that would break an existing database on the next
regeneration. So read_only counts as enforced only for manifest-declared
services, or where compose.yml sets read_only: true itself.
"""
from __future__ import annotations

import yaml

from boxmunge.commands.security_scan_inputs import hardening_profile, load_project_meta
from boxmunge.cve.hardening import calculate_hardening_penalty, hardening_profile_from_compose
from tests.test_commands.cve_helpers import make_box


def _box_with_compose_only(tmp_path, db: dict):
    paths = make_box(tmp_path)  # manifest declares web
    compose_path = paths.project_dir("demo") / "compose.yml"
    compose = yaml.safe_load(compose_path.read_text())
    compose["services"]["db"] = db
    compose_path.write_text(yaml.safe_dump(compose))
    return paths


def test_compose_only_service_without_read_only_is_penalised(tmp_path):
    paths = _box_with_compose_only(tmp_path, {"image": "postgres:16-alpine"})
    profile = hardening_profile(load_project_meta(paths, "demo"))
    assert profile.read_only is False
    assert profile.no_new_privileges is True  # the overlay does apply this
    assert calculate_hardening_penalty(profile) == 1


def test_compose_only_service_declaring_read_only_is_not_penalised(tmp_path):
    paths = _box_with_compose_only(tmp_path, {"image": "redis:7", "read_only": True})
    profile = hardening_profile(load_project_meta(paths, "demo"))
    assert profile.read_only is True
    assert calculate_hardening_penalty(profile) == 0


def test_manifest_service_relies_on_the_overlay_read_only(tmp_path):
    paths = make_box(tmp_path)  # web declared in the manifest, no read_only in compose
    profile = hardening_profile(load_project_meta(paths, "demo"))
    assert profile.read_only is True
    assert calculate_hardening_penalty(profile) == 0


def test_read_only_overlay_set_is_separate_from_the_overlay_set():
    compose = {"services": {"web": {}, "db": {}}}
    profile = hardening_profile_from_compose(
        compose, services_with_overlay={"web", "db"},
        services_with_read_only_overlay={"web"},
    )
    assert profile.read_only is False and profile.no_new_privileges is True
    both = hardening_profile_from_compose(compose, services_with_overlay={"web", "db"})
    assert both.read_only is True
