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

That guarantee holds for `_RUNTIME_FAMILIES`: an unlisted family means
`ecosystem_for_package` returns None, which `irrelevant_ecosystem` treats as
relevant. It does NOT hold for `_TRIVY_TYPE_TO_ECOSYSTEM`, which has the
opposite bias: a Trivy lang-pkgs `Type` this table doesn't recognise
contributes no ecosystem to `infer_runtimes`, which *shrinks* the inferred
runtime set, which makes *more* families look foreign, which de-escalates
*more* findings. An unmapped lang type is therefore a silent-exemption risk,
not a nuisance — see `unrecognised_lang_types`, which callers use to log the
drop (this module stays I/O-free, so it cannot log the drop itself).
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


def unrecognised_lang_types(lang_types: Iterable[str]) -> frozenset[str]:
    """Trivy lang-pkgs `Type` values that `infer_runtimes` silently drops.

    Unlike an unlisted `_RUNTIME_FAMILIES` entry, a dropped lang type biases
    TOWARD over-exemption (see module docstring): it shrinks the inferred
    runtime set rather than shrinking the set of packages eligible for
    de-escalation. This module is pure and does no logging itself — callers
    (the scan orchestrator) use this to log the drop once per scan.
    """
    return frozenset(
        lang_type
        for lang_type in lang_types
        if lang_type not in _TRIVY_TYPE_TO_ECOSYSTEM
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
        ValueError: `declared` is not a list/tuple, is an empty sequence, or
            contains a name outside VALID_ECOSYSTEMS.
    """
    if declared is not None:
        # A YAML `security.runtimes:` value that isn't a list is a manifest
        # mistake, not a variant spelling. Restrict to list/tuple explicitly
        # rather than trusting `Sequence` duck-typing: a bare string is a
        # Sequence[str] too and would silently shred into single characters
        # (frozenset("python") -> {'p','y',...}), and a mapping iterates
        # over its keys and would be silently accepted as a runtime set.
        # bool/int aren't iterable at all and would otherwise surface as an
        # uncaught TypeError from `frozenset(...)` below.
        if not isinstance(declared, (list, tuple)):
            raise ValueError(
                "declared runtimes must be a list, got "
                f"{type(declared).__name__}: {declared!r}"
            )
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


def irrelevant_ecosystem(
    finding: Finding, *, runtimes: frozenset[str],
) -> str | None:
    """The foreign runtime ecosystem this finding belongs to, or None.

    None means the finding is relevant — keep today's behaviour. Returning
    the ecosystem rather than a bool lets the policy engine reuse it in the
    operator explanation without a second lookup, so the decision and the
    message cannot disagree.

    All three conditions must hold; any doubt returns None (relevant).
    """
    if finding.pkg_class is not PkgClass.OS:
        return None
    ecosystem = ecosystem_for_package(finding.package)
    if ecosystem is None:
        return None
    if ecosystem in runtimes:
        return None
    return ecosystem


def is_irrelevant_to_project(
    finding: Finding, *, runtimes: frozenset[str],
) -> bool:
    """True iff this finding's package is a runtime the project never invokes."""
    return irrelevant_ecosystem(finding, runtimes=runtimes) is not None
