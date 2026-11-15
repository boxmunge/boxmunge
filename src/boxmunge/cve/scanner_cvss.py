"""CVSS parsing for Trivy findings: attack vector and base score.

Pure functions over Trivy's per-source `CVSS` block; no I/O.
"""

from __future__ import annotations

from enum import Enum
from typing import Any


class AttackVector(Enum):
    """CVSS Attack Vector — where the attacker must be to exploit.

    Reflects the AV: token in a CVSS v3/v4 vector string. v0.7.1 quarantine
    decisions gate on AV:N (Network) under non-paranoid postures: AV:L/A/P
    findings are reported as informational because they aren't reachable
    from the network surface a hardened web container exposes.
    """

    NETWORK = "Network"
    ADJACENT = "Adjacent"
    LOCAL = "Local"
    PHYSICAL = "Physical"


# CVSS AV: token → AttackVector. Trivy reports the canonical single-letter
# tokens; we tolerate the value being inside a longer vector string.
_AV_TOKEN_MAP: dict[str, AttackVector] = {
    "N": AttackVector.NETWORK,
    "A": AttackVector.ADJACENT,
    "L": AttackVector.LOCAL,
    "P": AttackVector.PHYSICAL,
}


# Source priority for resolving disagreements when multiple feeds report a
# CVE. NVD is preferred where present (most-curated), then redhat (good distro
# coverage), then ghsa (active for ecosystem packages). Anything else is taken
# in alphabetical order for determinism.
_CVSS_SOURCE_PRIORITY: tuple[str, ...] = ("nvd", "redhat", "ghsa")


def _parse_attack_vector(cvss: dict[str, Any]) -> AttackVector | None:
    """Extract the CVSS Attack Vector from a Trivy `CVSS` block.

    Trivy emits one entry per data source (nvd, redhat, ghsa, ...), each with
    optional V3Vector and/or V40Vector strings. We walk sources in a fixed
    priority order (nvd, redhat, ghsa, then any others alphabetically) and
    take the first parseable AV: token. V3 is preferred over V4 because the
    Trivy DB still has wider V3 coverage in 2026.

    Returns None when no source has a parseable vector — the caller treats
    that as "AV unknown", which under non-paranoid posture defaults to
    informational.
    """
    if not isinstance(cvss, dict) or not cvss:
        return None

    extras = sorted(k for k in cvss.keys() if k not in _CVSS_SOURCE_PRIORITY)
    ordered_sources = (*_CVSS_SOURCE_PRIORITY, *extras)

    for source in ordered_sources:
        entry = cvss.get(source)
        if not isinstance(entry, dict):
            continue
        for vector_key in ("V3Vector", "V40Vector"):
            vector = entry.get(vector_key)
            av = _extract_av_from_vector(vector)
            if av is not None:
                return av
    return None


def _parse_cvss_score(cvss: dict[str, Any]) -> float | None:
    """Highest V3Score across a Trivy `CVSS` block's sources, or the highest
    V2Score when no source has a V3 score, or None."""
    if not isinstance(cvss, dict):
        return None
    for key in ("V3Score", "V2Score"):
        scores = [e[key] for e in cvss.values()
                  if isinstance(e, dict) and isinstance(e.get(key), (int, float))
                  and not isinstance(e.get(key), bool)]
        if scores:
            return float(max(scores))
    return None


def _extract_av_from_vector(vector: Any) -> AttackVector | None:
    """Pull the AV: token out of a CVSS vector string.

    Tolerant of either prefix (CVSS:3.1/, CVSS:4.0/) and any token order.
    Returns None for non-strings, missing AV: token, or unrecognized values.
    """
    if not isinstance(vector, str) or not vector:
        return None
    for token in vector.split("/"):
        if not token.startswith("AV:"):
            continue
        value = token[3:].strip().upper()
        return _AV_TOKEN_MAP.get(value)
    return None
