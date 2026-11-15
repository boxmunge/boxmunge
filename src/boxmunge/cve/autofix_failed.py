# SPDX-License-Identifier: Apache-2.0
"""A patch that fails every time is not retried every run.

When an urgent or a nightly patch fails, what it was for is remembered per
trigger (cve.autofix_record, `state/autofix/<project>.failed`): the CVEs,
the exact images that carried them, each fixed version, the step, and
whether that failure would happen again the same way (`deterministic`: the
image cannot be patched, the patch does not fix it, the patched images are
not healthy) or may not (`transient`: the time budget, a mirror or Docker
error, a scan or swap failure). While the three are unchanged, a
deterministic failure holds the patch until something changes; a transient
one holds it for RETRY_TRANSIENT after its last try, then it is tried again.
While held, the scan does not queue that urgent patch (the policy's own
disposition stands, as when autofix cannot help) and the nightly flow does
not attempt it; the nightly digest lists it, "still unpatched since <date>:
<reason>". A retry that fails again at the same step, the same way, is not
alerted again (the fallback still applies); a different step or kind is.
Any change (a new base image, a new fixed version, another CVE) forgets it,
and the patch is tried again. A patch that succeeds, or finds nothing left to
patch, forgets it too; a release switch and a project delete remove the
record.

The record is advice, never a reason to stop: one that cannot be read or
written is logged as an error and the patch is tried as if there were none.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from boxmunge.cve.autofix_record import FailedPatch, Trigger, read_failed, write_failed
from boxmunge.log import log_error, log_operation
from boxmunge.state import StateError

if TYPE_CHECKING:
    from boxmunge.cve.autofix_run import AutofixOutcome
    from boxmunge.cve.policy_types import FindingDisposition, ProjectDecision
    from boxmunge.paths import BoxPaths

_COMPONENT = "autofix"
# A transient failure is tried again this long after its last try. Under a
# day: the try is stamped after its scan and build, so the next nightly
# scan comes a little under 24h later and must still retry it.
RETRY_TRANSIENT = timedelta(hours=20)

Pairs = Iterable[tuple["ProjectDecision", "FindingDisposition"]]


@dataclass(frozen=True)
class Signature:
    """What a patch depends on: the CVEs, the images that carry them, the fixes."""
    cves: tuple[str, ...]
    images: tuple[str, ...]
    fixes: tuple[str, ...]

    @classmethod
    def of(cls, pairs: Pairs) -> Signature:
        pairs = list(pairs)
        return cls(
            tuple(sorted({fd.finding.cve_id for _, fd in pairs})),
            tuple(sorted({d.image_ref for d, _ in pairs})),
            tuple(sorted({f"{fd.finding.cve_id} {fd.finding.package} "
                          f"{fd.finding.fixed_version}" for _, fd in pairs})))

    def matches(self, failed: FailedPatch) -> bool:
        return (self.cves, self.images, self.fixes) == (failed.cves, failed.images,
                                                         failed.fixes)


def _read(paths: BoxPaths, project: str) -> dict[Trigger, FailedPatch] | None:
    try:
        return read_failed(paths, project)
    except StateError as e:
        log_error(_COMPONENT, f"{project}: {e}; the patch is tried as if it never failed",
                  paths, project=project)
        return None


def _write(paths: BoxPaths, project: str, failed: dict[Trigger, FailedPatch]) -> None:
    try:
        write_failed(paths, project, failed)
    except StateError as e:
        log_error(_COMPONENT, f"{project}: {e}", paths, project=project)


def still_failing(paths: BoxPaths, project: str, trigger: Trigger, pairs: Pairs,
                  now: datetime) -> FailedPatch | None:
    """The remembered failure of this trigger's patch of `pairs` when it
    still holds the patch back: nothing it depends on changed, and it is
    deterministic or was last tried less than RETRY_TRANSIENT ago. A change
    forgets it (logged); None says to try the patch."""
    failed = _read(paths, project)
    if not failed or trigger not in failed:
        return None
    if Signature.of(pairs).matches(failed[trigger]):
        f = failed[trigger]
        if f.kind == "deterministic" or now - f.last_tried < RETRY_TRANSIENT:
            return f
        return None   # kept: a retry that fails the same way is not alerted again
    del failed[trigger]
    _write(paths, project, failed)
    log_operation(_COMPONENT, f"{project}: what its failed {trigger} patch depends on "
                  f"changed; it is tried again", paths, project=project)
    return None


def remember(paths: BoxPaths, project: str, trigger: Trigger, pairs: Pairs,
             outcome: AutofixOutcome, now: datetime) -> FailedPatch | None:
    """Record this trigger's failed patch of `pairs`. Returns the record
    when this is a repeat (the same signature, step and kind as the one
    remembered: compared by those, never by the reason's text), which is not
    alerted again; None for a new failure."""
    failed = _read(paths, project)
    if failed is None:
        return None
    sig = Signature.of(pairs)
    kind = "deterministic" if outcome.deterministic else "transient"
    prior = failed.get(trigger)
    if prior is not None and sig.matches(prior) and (prior.failed_step, prior.kind) == (
            outcome.failed_step, kind):
        failed[trigger] = replace(prior, last_tried=now)
        _write(paths, project, failed)
        return failed[trigger]
    failed[trigger] = FailedPatch(now, now, sig.cves, sig.images, sig.fixes,
                                  outcome.failed_step, kind, outcome.reason or "no reason given")
    _write(paths, project, failed)
    return None


def is_retry(paths: BoxPaths, project: str, trigger: Trigger, pairs: Pairs) -> bool:
    """The patch of `pairs` is a retry of the remembered failure (a
    transient one, due again): its start is not announced again."""
    failed = remembered(paths, project, trigger)
    return failed is not None and Signature.of(pairs).matches(failed)


def forget(paths: BoxPaths, project: str, trigger: Trigger) -> None:
    """The trigger's patch passed, or has nothing left to patch."""
    failed = _read(paths, project)
    if failed and trigger in failed:
        del failed[trigger]
        _write(paths, project, failed)


def remembered(paths: BoxPaths, project: str, trigger: Trigger) -> FailedPatch | None:
    """The trigger's remembered failure, as it is (for the digest)."""
    failed = _read(paths, project)
    return None if failed is None else failed.get(trigger)


def unpatched(failed: FailedPatch) -> str:
    """"still unpatched since 2026-11-14: build: <reason>"."""
    step = f"{failed.failed_step}: " if failed.failed_step else ""
    return f"still unpatched since {failed.at.date().isoformat()}: {step}{failed.reason}"
