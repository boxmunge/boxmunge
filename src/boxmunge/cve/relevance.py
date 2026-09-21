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
_RUNTIME_FAMILIES: dict[str, tuple[str, ...]] = {
    "perl": ("perl", "perl-base", "perl-modules-*", "libperl*"),
    "ruby": ("ruby", "ruby[0-9]*", "libruby*"),
    "php": ("php", "php[0-9]*", "php-*", "libphp*"),
    "python": ("python3", "python3.*", "python3-*", "libpython3*"),
    "node": ("nodejs", "libnode*"),
    "tcl": ("tcl", "tcl[0-9]*", "libtcl*"),
    "lua": ("lua", "lua[0-9]*", "liblua*"),
}

# The vocabulary accepted in a manifest's security.runtimes. The union of
# both tables: an ecosystem may be declarable without being inferrable
# (perl has no Trivy lang type, but declaring it is how an operator says
# "this project really does invoke Perl").
VALID_ECOSYSTEMS: frozenset[str] = frozenset(
    set(_TRIVY_TYPE_TO_ECOSYSTEM.values()) | set(_RUNTIME_FAMILIES)
)


def infer_runtimes(findings: Iterable[Finding]) -> frozenset[str]:
    """Ecosystems this project runs, inferred from its lang-pkgs findings.

    An empty set is a valid answer, not a failure: a static site served by
    nginx runs no language runtime, so every family is foreign to it.
    """
    return frozenset(
        eco
        for f in findings
        if f.pkg_class is PkgClass.LANG and f.pkg_type
        for eco in (_TRIVY_TYPE_TO_ECOSYSTEM.get(f.pkg_type),)
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
    findings: Iterable[Finding], *, declared: Sequence[str] | None = None,
) -> frozenset[str]:
    """Declared runtimes if the manifest specifies them, else inferred.

    Explicit beats inferred: a declaration replaces inference rather than
    adding to it, so an operator who declares the set gets exactly that set.
    """
    if declared:
        return frozenset(declared)
    return infer_runtimes(findings)


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
