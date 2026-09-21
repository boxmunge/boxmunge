# SPDX-License-Identifier: Apache-2.0
"""Package relevance — is this project even capable of running the affected code?

The trust ladder grades how bad a CVE is. It never asks whether the project
uses the affected package at all. A Python app cannot execute a Perl regex
bug, however Critical Debian rates it.

Conservative by construction: only packages positively identified as a
language runtime are eligible for de-escalation. Anything unrecognised —
unknown package, unknown class, unlisted family — is treated as relevant and
keeps today's behaviour. Drift causes missed de-escalation (a nuisance),
never silent exemption (a hazard).
"""
from __future__ import annotations

from collections.abc import Iterable, Sequence
from fnmatch import fnmatchcase

from boxmunge.cve.scanner import Finding, PkgClass

# Trivy lang-pkgs Type → ecosystem. Used to infer what a project actually
# runs from its own dependency manifest.
_TRIVY_TYPE_TO_ECOSYSTEM: dict[str, str] = {
    "python-pkg": "python", "pip": "python", "poetry": "python",
    "node-pkg": "node", "npm": "node", "yarn": "node", "pnpm": "node",
    "gobinary": "go", "gomod": "go",
    "gemspec": "ruby", "bundler": "ruby",
    "composer": "php",
    "jar": "java", "pom": "java", "gradle": "java",
    "cargo": "rust",
    "nuget": "dotnet", "dotnet-core": "dotnet",
}

# Ecosystem → OS package-name glob patterns. Deliberately narrow: openssl,
# libc, zlib and friends are absent by design and so keep today's behaviour.
#
# Standalone interpreters ONLY. Embeddable interpreter libraries
# (libperl*, liblua*, libtcl*, ...) are deliberately absent: redis,
# haproxy and nginx-extras link liblua, mod_perl links libperl, so a CVE
# there IS reachable from a project written in another language. Matching
# them would exempt a genuinely reachable bug.
_RUNTIME_FAMILIES: dict[str, tuple[str, ...]] = {
    "perl": ("perl", "perl-base", "perl-modules-*"),
    "ruby": ("ruby", "ruby[0-9]*"),
    "php": ("php", "php[0-9]*", "php-*"),
    "python": ("python3", "python3.*", "python3-*"),
    "node": ("nodejs",),
    "tcl": ("tcl", "tcl[0-9]*"),
    "lua": ("lua", "lua[0-9]*"),
}

# The vocabulary accepted in a manifest's security.runtimes. The union of
# both tables: an ecosystem may be declarable without being inferrable
# (perl has no Trivy lang type, but declaring it is how an operator says
# "this project really does invoke Perl").
VALID_ECOSYSTEMS: frozenset[str] = frozenset(
    set(_TRIVY_TYPE_TO_ECOSYSTEM.values()) | set(_RUNTIME_FAMILIES)
)


def infer_runtimes(lang_types: Iterable[str]) -> frozenset[str]:
    """Ecosystems this project runs, inferred from its lang-pkgs Result types.

    Takes the Trivy `Type` values of lang-pkgs *results*, not findings:
    Trivy only emits a finding for a package with a known CVE, so a project
    whose dependencies are fully patched has zero lang-pkgs findings but
    still has a lang-pkgs result (empty Vulnerabilities). Inferring from
    findings would mean patching your dependencies strips the relevance
    gate's protection for your own runtime — see ScanResult.lang_types.

    An empty set is a valid answer, not a failure: a static site served by
    nginx runs no language runtime, so every family is foreign to it.
    """
    return frozenset(
        eco
        for lang_type in lang_types
        for eco in (_TRIVY_TYPE_TO_ECOSYSTEM.get(lang_type),)
        if eco is not None
    )


def ecosystem_for_package(package: str) -> str | None:
    """The language runtime this OS package belongs to, or None.

    None means "not a recognised language runtime" — which includes every
    ordinary system library, and is what keeps openssl quarantinable.
    """
    if not package:
        return None
    for ecosystem, patterns in _RUNTIME_FAMILIES.items():
        if any(fnmatchcase(package, pat) for pat in patterns):
            return ecosystem
    return None


def effective_runtimes(
    lang_types: Iterable[str], *, declared: Sequence[str] | None = None,
) -> frozenset[str]:
    """Declared runtimes if the manifest specifies them, else inferred.

    Explicit beats inferred: a declaration replaces inference rather than
    adding to it, so an operator who declares the set gets exactly that set.

    `declared=None` means "no declaration — infer instead". `declared=[]`
    is not a way to say "no runtimes": it's almost certainly a manifest
    mistake (an empty list, an unset env var), and silently falling back to
    inference would hide that mistake. Likewise a typo'd runtime name must
    fail loudly rather than silently granting the typo maximal exemption
    power, so both are raised rather than absorbed.

    Raises:
        ValueError: `declared` is an empty sequence, or contains a name
            outside VALID_ECOSYSTEMS.
    """
    if declared is not None:
        declared_set = frozenset(declared)
        if not declared_set:
            raise ValueError("declared runtimes must not be empty")
        unknown = declared_set - VALID_ECOSYSTEMS
        if unknown:
            raise ValueError(
                f"declared runtime(s) not recognised: {sorted(unknown)}"
            )
        return declared_set
    return infer_runtimes(lang_types)


def is_irrelevant_to_project(
    finding: Finding, *, runtimes: frozenset[str],
) -> bool:
    """True iff this finding's package is a runtime the project never invokes.

    All three conditions must hold; any doubt returns False (relevant).
    """
    if finding.pkg_class is not PkgClass.OS:
        return False
    ecosystem = ecosystem_for_package(finding.package)
    if ecosystem is None:
        return False
    return ecosystem not in runtimes
