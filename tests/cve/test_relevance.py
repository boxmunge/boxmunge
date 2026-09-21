# SPDX-License-Identifier: Apache-2.0
import pytest

from boxmunge.cve.relevance import (
    VALID_ECOSYSTEMS,
    ecosystem_for_package,
    effective_runtimes,
    infer_runtimes,
    is_irrelevant_to_project,
    unrecognised_lang_types,
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
#
# infer_runtimes takes lang-pkgs Result *types* (as scanner._parse_lang_types
# collects them), not Finding objects: Trivy only emits a finding for a
# package with a known CVE, so a project with fully patched dependencies has
# zero lang-pkgs findings but still has the lang-pkgs result itself.

def test_infer_runtimes_from_python_lang_pkgs():
    assert infer_runtimes(["python-pkg"]) == frozenset({"python"})


def test_infer_runtimes_unions_multiple_ecosystems():
    assert infer_runtimes(["python-pkg", "node-pkg"]) == frozenset({"python", "node"})


def test_infer_runtimes_ignores_unrecognised_type():
    assert infer_runtimes(["cobol-pkg"]) == frozenset()


def test_infer_runtimes_static_site_has_no_runtimes():
    assert infer_runtimes([]) == frozenset()


# ---- unrecognised lang types (final-review Fix 2) ----
#
# infer_runtimes silently drops any Trivy lang-pkgs Type absent from
# _TRIVY_TYPE_TO_ECOSYSTEM. That biases toward OVER-exemption (it shrinks the
# runtime set), the opposite of an unlisted _RUNTIME_FAMILIES entry — so the
# drop must be reportable to a caller that can log it (relevance.py itself
# stays pure/I/O-free).

@pytest.mark.parametrize("lang_type,expected", [
    ("conda-pkg", frozenset({"conda-pkg"})),
    ("pipenv", frozenset({"pipenv"})),
    ("uv", frozenset({"uv"})),
    ("python-pkg", frozenset()),
])
def test_unrecognised_lang_types_reports_unmapped_types(lang_type, expected):
    assert unrecognised_lang_types([lang_type]) == expected


def test_unrecognised_lang_types_mixed_input():
    assert unrecognised_lang_types(["python-pkg", "conda-pkg", "uv"]) == (
        frozenset({"conda-pkg", "uv"})
    )


def test_unrecognised_lang_types_empty_for_no_input():
    assert unrecognised_lang_types([]) == frozenset()


def test_infer_runtimes_shrinks_silently_on_conda_only_image():
    """Reproduces the failure scenario directly: a conda-based Python image
    reports only the conda-pkg lang type, which infer_runtimes cannot map to
    any ecosystem — the inferred set is empty even though the image plainly
    runs Python."""
    assert infer_runtimes(["conda-pkg"]) == frozenset()
    assert unrecognised_lang_types(["conda-pkg"]) == frozenset({"conda-pkg"})


def test_own_runtime_stays_relevant_even_when_dependencies_are_clean():
    """Regression: patching your deps must not strip protection for your
    own runtime.

    A Node app whose npm dependencies are fully patched produces zero
    lang-pkgs findings, but Trivy still reports the lang-pkgs Result row
    for the manifest it scanned (Type "node-pkg", empty Vulnerabilities).
    infer_runtimes must read that row, not the (empty) findings — otherwise
    a Critical CVE in the base image's own nodejs OS package would be
    wrongly judged irrelevant to a project that plainly runs Node.
    """
    lang_types = ["node-pkg"]  # lang-pkgs result present; no vulnerable npm pkgs
    runtimes = effective_runtimes(lang_types)
    finding = _finding("nodejs")  # Critical CVE in the base image's nodejs OS pkg
    assert is_irrelevant_to_project(finding, runtimes=runtimes) is False


# ---- family matching ----

@pytest.mark.parametrize("package,expected", [
    ("perl-base", "perl"),
    ("perl", "perl"),
    ("perl-modules-5.40", "perl"),
    ("ruby3.1", "ruby"),
    ("php8.2", "php"),
    ("python3.11", "python"),
    ("nodejs", "node"),
    ("tcl8.6", "tcl"),
    ("lua5.4", "lua"),
])
def test_ecosystem_for_package_matches_families(package, expected):
    assert ecosystem_for_package(package) == expected


@pytest.mark.parametrize("package", [
    "openssl", "libc6", "zlib1g", "libexpat1", "libssl3", "curl", "",
    # Embeddable interpreter libraries: linked into other-language processes
    # (redis/haproxy/nginx-extras link liblua, mod_perl links libperl, mod_wsgi
    # / embedding apps link libpython3), so a CVE there IS reachable from a
    # project written in another language and must never be exempted.
    "libperl5.40", "liblua5.1-0", "libluajit-5.1-2", "libtcl8.6",
    "libpython3.11-stdlib",
    # Mutation-testing guards: names that a loosened glob (e.g. "perl*",
    # "python*", "node*") would wrongly match.
    "libapache2-mod-php", "perl-openssl", "ruby-openssl", "rubygems",
    "nodejs-doc", "node-tar", "luajit", "phpunit", "python-is-python3",
    "py3-cryptography", "python2.7",
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
    """An app's own dependency is by definition used by the app.

    Uses "perl-base" — a name that *does* match the perl family — so this
    actually exercises the pkg_class guard rather than passing merely
    because the package name is unrecognised.
    """
    assert is_irrelevant_to_project(
        _finding("perl-base", pkg_class=PkgClass.LANG, pkg_type="python-pkg"),
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
    assert effective_runtimes(["python-pkg"], declared=["perl"]) == frozenset({"perl"})


def test_effective_runtimes_falls_back_to_inference():
    assert effective_runtimes(["python-pkg"], declared=None) == frozenset({"python"})


def test_effective_runtimes_empty_declared_raises():
    """declared=[] is not "no runtimes" — it's almost certainly a manifest
    mistake, and silently falling back to inference would hide it."""
    with pytest.raises(ValueError):
        effective_runtimes(["python-pkg"], declared=[])


def test_effective_runtimes_unknown_declared_raises():
    """A typo'd runtime name must fail loudly, not silently grant the typo
    maximal exemption power."""
    with pytest.raises(ValueError):
        effective_runtimes(["python-pkg"], declared=["pyhton"])


def test_effective_runtimes_bare_string_declared_raises():
    """A bare string is a Sequence[str] too — without a type check it would
    silently shred into single characters (frozenset("python") -> six
    single-letter "runtimes") instead of failing loudly."""
    with pytest.raises(ValueError):
        effective_runtimes(["python-pkg"], declared="python")


def test_effective_runtimes_mapping_declared_raises():
    """A mapping iterates over its keys and would otherwise be silently
    accepted as a runtime set — exactly the fallback-that-hides-a-mistake
    this project's rules forbid."""
    with pytest.raises(ValueError):
        effective_runtimes(["python-pkg"], declared={"python": True})


def test_effective_runtimes_bool_declared_raises():
    """bool isn't iterable; must fail as ValueError, not an uncaught
    TypeError that would escape the caller's except clause."""
    with pytest.raises(ValueError):
        effective_runtimes(["python-pkg"], declared=True)


def test_effective_runtimes_int_declared_raises():
    """int isn't iterable either — same requirement as the bool case."""
    with pytest.raises(ValueError):
        effective_runtimes(["python-pkg"], declared=5)


def test_valid_ecosystems_covers_every_family_and_inferred_name():
    assert VALID_ECOSYSTEMS == frozenset({
        "python", "node", "go", "ruby", "php", "java", "rust", "dotnet",
        "perl", "tcl", "lua",
    })
