# SPDX-License-Identifier: Apache-2.0
"""The CVE hardening penalty sees what the overlay applies, not only compose.yml.

A manifest relaxation (`security.no_new_privileges: false`, `cap_add`) is
emitted by the overlay; compose.yml alone does not show it, so it must still
weaken the project's hardening profile.
"""
from __future__ import annotations

from boxmunge.commands.security_scan_inputs import ProjectMeta, hardening_profile
from boxmunge.cve.hardening import calculate_hardening_penalty
from boxmunge.cve.policy import parse_posture

MODEL = {"services": {"web": {"image": "nginx:1"}, "db": {"image": "postgres:16"}}}


def _meta(manifest: dict) -> ProjectMeta:
    return ProjectMeta(manifest=manifest, posture_str="balanced",
                       posture=parse_posture("balanced"), dangerously=False,
                       declared_runtimes=None, hosts=[], compose_files=["compose.yml"])


def _profile(security: dict | None = None, web: dict | None = None):
    manifest = {"services": {"web": {"port": 80, "routes": [{"path": "/"}],
                                     **({"security": web} if web else {})},
                             "db": {"internal": True}},
                **({"security": security} if security else {})}
    return hardening_profile(_meta(manifest), MODEL)


def test_overlay_defaults_carry_no_penalty() -> None:
    assert calculate_hardening_penalty(_profile()) == 0


def test_manifest_no_new_privileges_false_is_a_penalty() -> None:
    profile = _profile(web={"no_new_privileges": False})
    assert not profile.no_new_privileges
    assert calculate_hardening_penalty(profile) == 1


def test_project_level_no_new_privileges_false_reaches_undeclared_services() -> None:
    manifest = {"services": {"web": {"port": 80, "routes": [{"path": "/"}]}},
                "security": {"no_new_privileges": False}}
    assert not hardening_profile(_meta(manifest), MODEL).no_new_privileges


def test_manifest_cap_add_is_a_penalty() -> None:
    profile = _profile(web={"cap_add": ["NET_RAW"]})
    assert profile.extra_caps_added
    assert calculate_hardening_penalty(profile) == 1


def test_compose_cap_add_still_counts() -> None:
    model = {"services": {"web": {"image": "nginx:1", "cap_add": ["NET_RAW"]}}}
    manifest = {"services": {"web": {"port": 80, "routes": [{"path": "/"}]}}}
    assert hardening_profile(_meta(manifest), model).extra_caps_added


def test_off_service_is_judged_literally_and_its_manifest_cap_add_counts() -> None:
    off = {"profile": "off", "reason": "a test", "cap_add": ["NET_RAW"]}
    profile = _profile(web=off)
    assert not profile.no_new_privileges and profile.extra_caps_added


def test_compose_only_service_is_read_only_only_when_compose_says_so() -> None:
    """The overlay gives services the manifest does not declare no read-only
    root (compose.py), so only compose.yml's own `read_only: true` counts."""
    manifest = {"services": {"web": {"port": 80, "routes": [{"path": "/"}]}}}
    profile = hardening_profile(_meta(manifest), MODEL)
    assert not profile.read_only
    assert calculate_hardening_penalty(profile) == 1
    model = {"services": {"web": {"image": "nginx:1"},
                          "db": {"image": "postgres:16", "read_only": True}}}
    assert hardening_profile(_meta(manifest), model).read_only


def test_declared_service_gets_the_overlays_read_only() -> None:
    manifest = {"services": {"web": {"port": 80, "routes": [{"path": "/"}]},
                             "db": {"internal": True}}}
    assert hardening_profile(_meta(manifest), MODEL).read_only
