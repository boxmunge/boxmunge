# SPDX-License-Identifier: Apache-2.0
"""`prod-deploy --accept-stale-kev`: the audited KEV acceptance, carried
through a deploy to its quarantine gate.

With no usable CISA KEV catalog (never fetched, or the cache unreadable),
the routes that lift a quarantine refuse (cve.lift_rule), and `security
resume --accept-stale-kev` is the audited way past that. A fix deploy
hits the same refusal at the gate (quarantine_gate) and used to need that
resume first, which brought back the images the project ran when it was
quarantined until the deploy replaced them. `prod-deploy <project>
--accept-stale-kev` accepts the same thing for the release it deploys,
the same way: only with no usable catalog (a stale catalog that lists a
CVE still in the release's images refuses as before: a fresh one would
too), logged before anything starts, and alerted at priority 1 with the
lift. Without anything to accept it says so, as resume does.

prod-deploy sets the acceptance for its own run (prod_deploy_acceptance)
and the gate reads it. It is scoped to that one command instead of being
threaded through every route a prod-deploy takes to the gate (a bundle, a
git ref, --redeploy, a resumed install). Any other route there (promote,
rollback, the TUI, MCP) has none, and is offered the resume.
"""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

from boxmunge.cve.lift_rule import ACCEPT_FLAG, KevLiftCheck, fresh_data_advice
from boxmunge.cve.quarantine import is_quarantined
from boxmunge.data_dirs import ReleaseStateError
from boxmunge.log import log_warning
from boxmunge.paths import BoxPaths
from boxmunge.redeploy_hint import redeploy_command
from boxmunge.release_txn import load_txn, rerun_command


@dataclass
class _Acceptance:
    accepted: bool
    consulted: bool = False


_CURRENT: ContextVar[_Acceptance | None] = ContextVar("prod_deploy_kev_acceptance",
                                                      default=None)


@contextmanager
def prod_deploy_acceptance(paths: BoxPaths, project: str, accepted: bool) -> Iterator[None]:
    """For the length of one prod-deploy: whether its operator passed
    --accept-stale-kev. A flag no gate consulted is said to have done
    nothing."""
    acceptance = _Acceptance(accepted)
    token = _CURRENT.set(acceptance)
    try:
        yield
    finally:  # also when the command exits from inside
        _CURRENT.reset(token)
        if accepted and not acceptance.consulted:
            why = ("the deploy stopped before the quarantine's KEV check" if
                   is_quarantined(project, paths) else f"{project} is not CVE-quarantined")
            print(f"  {ACCEPT_FLAG}: nothing to accept: {why}.")


def accept_at_gate(project: str, check: KevLiftCheck, paths: BoxPaths) -> str | None:
    """The refusal this prod-deploy's --accept-stale-kev lets through, or
    None. Logged before anything starts; the lift alerts it."""
    acceptance = _CURRENT.get()
    if acceptance is None or not acceptance.accepted:
        return None
    acceptance.consulted = True
    if check.refusal is None:
        print(f"  {ACCEPT_FLAG}: nothing to accept: "
              + ("the KEV catalog is fresh." if check.stale is None else
                 "the KEV catalog is stale but lists no CVE in the images, so the release "
                 "goes ahead without it (and the lift is alerted as on a stale catalog)."))
        return None
    if not check.acceptable:
        return None
    print(f"  {ACCEPT_FLAG}: deploying although {check.refusal}. A CVE that is actively "
          f"exploited may go live with this release.")
    log_warning("deploy", f"{ACCEPT_FLAG}: release cleared with no usable KEV catalog",
                paths, project=project,
                detail={"reason": check.refusal, "kev_stale": check.stale})
    return check.refusal


def gate_exits(project: str, check: KevLiftCheck, paths: BoxPaths) -> list[str]:
    """What gets a fix deploy the gate refused through, from the route it
    took there."""
    acceptance = _CURRENT.get()
    if not check.acceptable:
        exits = ["Ship a release without those CVEs.",
                 f"Or: {fresh_data_advice()}; then deploy again."]
        if acceptance is not None and acceptance.accepted:
            exits.append(f"{ACCEPT_FLAG} does not apply: a fresh catalog would refuse this "
                         f"release too.")
        return exits
    if acceptance is not None:
        return [f"{fresh_data_advice()}; then deploy again.",
                f"Or, having judged the risk, deploy it anyway: "
                f"{_again(project, paths)} (logged, and alerted with the lift)."]
    return [
        f"{fresh_data_advice()}; then deploy again.",
        f"Or lift the quarantine first with `boxmunge security resume {project} "
        f"{ACCEPT_FLAG}` (logged and alerted), then deploy again. That resume brings the "
        f"images the project ran when it was quarantined back online until this release "
        f"replaces them.",
        f"Under strict or paranoid, if that resume refuses a finding that is still "
        f"quarantine-level in those images: `boxmunge security suppress <CVE> --project "
        f"{project} --until <YYYY-MM-DD> --reason <text>`, then the resume with "
        f"{ACCEPT_FLAG}, then this deploy, then `boxmunge security unsuppress <CVE> "
        f"--project {project}`.",
    ]


def _again(project: str, paths: BoxPaths) -> str:
    """The prod-deploy that deploys this release again with the flag."""
    try:
        txn = load_txn(paths, project)
    except ReleaseStateError as e:
        return f"run this prod-deploy again with {ACCEPT_FLAG} once {e} is resolved"
    if txn is None:  # --redeploy of the installed release: no install is opened
        command = redeploy_command(paths, project)
    elif txn.source in ("bundle", "git"):
        command = rerun_command(project, txn)
    else:
        return f"run this prod-deploy again with {ACCEPT_FLAG}"
    return f"`{command} {ACCEPT_FLAG}`"
