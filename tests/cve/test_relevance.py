# SPDX-License-Identifier: Apache-2.0
import pytest

from boxmunge.cve.relevance import (
    VALID_ECOSYSTEMS,
    ecosystem_for_package,
    effective_runtimes,
    infer_runtimes,
    is_irrelevant_to_project,
)
from boxmunge.cve.scanner import Finding, PkgClass, Severity


def _finding(package, *, pkg_class=PkgClass.OS, pkg_type="debian"):
    return Finding(
        cve_id="CVE-2026-0001",
        severity=Severity.CRITICAL,
        package=package,
        installed_version="1.0",
        fixed_version=None,
        title="t",
        primary_url=None,
        pkg_class=pkg_class,
        pkg_type=pkg_type,
    )


# ---- inference ----

def test_infer_runtimes_from_python_lang_pkgs():
    findings = [_finding("fastapi", pkg_class=PkgClass.LANG, pkg_type="python-pkg")]
    assert infer_runtimes(findings) == frozenset({"python"})


def test_infer_runtimes_unions_multiple_ecosystems():
    findings = [
        _finding("fastapi", pkg_class=PkgClass.LANG, pkg_type="python-pkg"),
        _finding("express", pkg_class=PkgClass.LANG, pkg_type="node-pkg"),
    ]
    assert infer_runtimes(findings) == frozenset({"python", "node"})


def test_infer_runtimes_ignores_os_pkgs():
    """OS packages say nothing about what the app runs."""
    findings = [_finding("perl-base")]
    assert infer_runtimes(findings) == frozenset()


def test_infer_runtimes_ignores_unrecognised_type():
    findings = [_finding("x", pkg_class=PkgClass.LANG, pkg_type="cobol-pkg")]
    assert infer_runtimes(findings) == frozenset()


def test_infer_runtimes_static_site_has_no_runtimes():
    assert infer_runtimes([]) == frozenset()


# ---- family matching ----

@pytest.mark.parametrize("package,expected", [
    ("perl-base", "perl"),
    ("perl", "perl"),
    ("perl-modules-5.40", "perl"),
    ("libperl5.40", "perl"),
    ("ruby3.1", "ruby"),
    ("php8.2", "php"),
    ("python3.11", "python"),
    ("libpython3.11-stdlib", "python"),
    ("nodejs", "node"),
    ("tcl8.6", "tcl"),
    ("lua5.4", "lua"),
])
def test_ecosystem_for_package_matches_families(package, expected):
    assert ecosystem_for_package(package) == expected


@pytest.mark.parametrize("package", [
    "openssl", "libc6", "zlib1g", "libexpat1", "libssl3", "curl", "",
])
def test_ecosystem_for_package_returns_none_for_non_runtime(package):
    """The over-exemption guard: ordinary OS libs are not runtime families."""
    assert ecosystem_for_package(package) is None


# ---- the predicate ----

def test_perl_base_is_irrelevant_to_python_project():
    assert is_irrelevant_to_project(
        _finding("perl-base"), runtimes=frozenset({"python"}),
    ) is True


def test_perl_base_is_relevant_when_perl_declared():
    assert is_irrelevant_to_project(
        _finding("perl-base"), runtimes=frozenset({"python", "perl"}),
    ) is False


def test_openssl_is_relevant_to_python_project():
    """Regression guard: the gate must never exempt a reachable OS library."""
    assert is_irrelevant_to_project(
        _finding("openssl"), runtimes=frozenset({"python"}),
    ) is False


def test_python_os_package_is_relevant_to_python_project():
    assert is_irrelevant_to_project(
        _finding("python3.11"), runtimes=frozenset({"python"}),
    ) is False


def test_lang_pkg_is_never_irrelevant():
    """An app's own dependency is by definition used by the app."""
    assert is_irrelevant_to_project(
        _finding("some-perl-gem", pkg_class=PkgClass.LANG, pkg_type="python-pkg"),
        runtimes=frozenset({"python"}),
    ) is False


def test_unknown_pkg_class_is_never_irrelevant():
    """Fail toward today's behaviour, never toward silent exemption."""
    assert is_irrelevant_to_project(
        _finding("perl-base", pkg_class=PkgClass.UNKNOWN, pkg_type=None),
        runtimes=frozenset({"python"}),
    ) is False


# ---- effective runtimes ----

def test_effective_runtimes_declared_replaces_inference():
    findings = [_finding("fastapi", pkg_class=PkgClass.LANG, pkg_type="python-pkg")]
    assert effective_runtimes(findings, declared=["perl"]) == frozenset({"perl"})


def test_effective_runtimes_falls_back_to_inference():
    findings = [_finding("fastapi", pkg_class=PkgClass.LANG, pkg_type="python-pkg")]
    assert effective_runtimes(findings, declared=None) == frozenset({"python"})


def test_valid_ecosystems_covers_every_family_and_inferred_name():
    from boxmunge.cve.relevance import _RUNTIME_FAMILIES, _TRIVY_TYPE_TO_ECOSYSTEM
    assert set(_RUNTIME_FAMILIES) <= VALID_ECOSYSTEMS
    assert set(_TRIVY_TYPE_TO_ECOSYSTEM.values()) <= VALID_ECOSYSTEMS
