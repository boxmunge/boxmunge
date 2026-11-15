# SPDX-License-Identifier: Apache-2.0
"""The deploy guard: a release that carries a known-exploited CVE is refused.

Someone who stages, deploys, promotes or rolls back a project is working on
it, so the box tells them to fix a known-exploited CVE in the repo rather
than ship it (autofix never runs inside a deploy). Every image the release
would start is scanned, whether the project is quarantined or not, after
the build and pull and before anything is stopped, started or switched
(release_config, staging_bringup), and before a quarantined project's own
gate (quarantine_gate), which reads the same scan from the cache
(cve.scan_cache). The findings are judged afresh against today's
known-exploited lists, never against a stored scan that may predate a new
listing.

The guard refuses:
- a finding listed by CISA's KEV or the EU's (full KEV), under any posture;
- under paranoid, a VulnCheck-only listing too;
- a CVE autofix patched in the running release (patched_cves);
- a scan that failed or did not cover every image: nothing shows the
  release is free of them;
- the CISA catalog the way the quarantine gate judges it (cve.lift_rule):
  a stale catalog refuses a CVE its cached copy lists, and with no usable
  catalog the release is refused unless prod-deploy's --accept-stale-kev
  accepts that (kev_acceptance; alerted here for a project not
  quarantined, whose lift would otherwise alert it).

The refusal names each CVE, its package, the installed and the fixed
version and the lists that name it, then how to fix it in the repo.
`--allow-security-regression --reason "<why>"` on stage, prod-deploy,
promote or rollback deploys it anyway: logged, and alerted (the CLI routes
write no action audit; that is the API's). MCP and the TUI have no flag,
so they get the refusal and its guidance. A flag no refusal needed says so.
"""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from boxmunge.commands.argv import Args, usage_error
from boxmunge.commands.kev_acceptance import accept_at_guard, stale_exit
from boxmunge.commands.quarantine_gate import scan_release_images, start_images
from boxmunge.commands.security_scan_core import ProjectScan
from boxmunge.commands.security_scan_inputs import ProjectMeta, ScanTarget, project_meta
from boxmunge.compose_images import describe_image
from boxmunge.compose_resolve import ComposeResolveError
from boxmunge.cve.exploited import ExploitedSource, is_full_kev
from boxmunge.cve.kev import KevCatalog, load_kev
from boxmunge.cve.lift_rule import KevLiftCheck, fresh_data_advice
from boxmunge.cve.policy import FindingDisposition
from boxmunge.cve.policy_types import Posture, listing_label
from boxmunge.cve.scanner import ScannerError
from boxmunge.docker_run import DockerError
from boxmunge.log import log_warning
from boxmunge.notify import notify
from boxmunge.paths import BoxPaths
from boxmunge.release_target import DeployRefused, ReleaseTarget
from boxmunge.state import StateError

OVERRIDE_FLAG = "--allow-security-regression"
REASON_OPTION = "--reason"
DEPLOY_ANYWAY = f'To deploy anyway: {OVERRIDE_FLAG} {REASON_OPTION} "<why>"'
FIX_IN_REPO = ("Fix it in the repo: bump the base image, or upgrade the package in the "
               "Dockerfile, then deploy again. " + DEPLOY_ANYWAY)


class SecurityRegressionRefused(DeployRefused):
    """The release carries a known-exploited CVE (or could not be shown not
    to); nothing was started. ``reasons`` are the problems without the
    closing exit, for a route with exits of its own (rollback)."""

    def __init__(self, reasons: list[str], closing: str) -> None:
        self.reasons = reasons
        self.closing = closing
        super().__init__([*reasons, closing])

    def with_extra(self, line: str) -> SecurityRegressionRefused:
        return SecurityRegressionRefused([*self.reasons, line], self.closing)


@dataclass
class _Override:
    project: str
    reason: str | None
    checked: bool = False    # the guard ran
    consulted: bool = False  # and the flag let a refusal through
    recorded: set[tuple[str, ...]] = field(default_factory=set)


_CURRENT: ContextVar[_Override | None] = ContextVar("security_regression_override",
                                                    default=None)


def override_reason(command: str, parsed: Args) -> str | None:
    """The --reason of a command's --allow-security-regression, or None
    without the flag; a usage error when one is given without the other."""
    reason = parsed.get(REASON_OPTION)
    if not parsed.has(OVERRIDE_FLAG):
        if reason is not None:
            usage_error(command, f"{REASON_OPTION} goes with {OVERRIDE_FLAG}")
        return None
    if reason is None or not reason.strip():
        usage_error(command, f'{OVERRIDE_FLAG} needs {REASON_OPTION} "<why>": the reason '
                             f"is logged and alerted")
    return reason.strip()


@contextmanager
def regression_override(paths: BoxPaths, project: str, reason: str | None) -> Iterator[None]:
    """For the length of one command: the --reason its operator gave with
    --allow-security-regression (None: no flag). A flag no refusal needed
    is said to have done nothing."""
    if reason is not None and not reason.strip():
        raise ValueError(f"{OVERRIDE_FLAG} needs a non-empty reason")
    override = _Override(project, reason)
    token = _CURRENT.set(override)
    try:
        yield
    finally:  # also when the command exits from inside
        _CURRENT.reset(token)
        if reason is not None and not override.consulted:
            why = ("the deploy guard found no known-exploited CVE in the release's images"
                   if override.checked else "the deploy stopped before the deploy guard ran")
            print(f"  {OVERRIDE_FLAG}: nothing to override: {why}.")


def patched_cves(paths: BoxPaths, project: str) -> frozenset[str]:
    """The CVEs autofix patched in the running release: a release that
    brings one back is refused. Autofix patching arrives with part 2 of the
    0.12 autofix work; until then nothing is patched."""
    return frozenset()


def _line(f: FindingDisposition, image_ref: str, service: str, listed: str) -> str:
    fix = (f"fixed in {f.finding.fixed_version}" if f.finding.fixed_version
           else "no fixed version published yet")
    return (f"{f.finding.cve_id} in {f.finding.package} {f.finding.installed_version} "
            f"({fix}), service {service} ({describe_image(image_ref)}): {listed}")


def _listed(f: FindingDisposition, *, paranoid: bool, patched: frozenset[str],
            stale_listed: frozenset[str], stale: str | None) -> str | None:
    """Why the guard refuses this finding, or None."""
    sources = f.exploited_by
    if is_full_kev(sources):
        return f"listed as actively exploited by {listing_label(sources)}"
    if f.finding.cve_id in stale_listed:
        return (f"listed as actively exploited by the cached CISA KEV catalog, which is "
                f"stale ({stale}); a stale catalog cannot show that has changed")
    if paranoid and ExploitedSource.VULNCHECK in sources:  # no suppression applies there
        return f"listed as actively exploited by {listing_label(sources)} (paranoid refuses it)"
    if f.finding.cve_id in patched:
        return "autofix patched it in the running release; this release brings it back"
    return None


def _cve_lines(paths: BoxPaths, project: str, meta: ProjectMeta, scan: ProjectScan,
               targets: list[ScanTarget], kev: KevCatalog, stale: str | None) -> list[str]:
    services: dict[str, list[str]] = {}
    for t in targets:
        services.setdefault(t.image_ref, []).append(t.service)
    # A stale catalog is not in the known-exploited index; its cached copy still counts.
    stale_listed = kev.cve_ids if stale is not None else frozenset()
    patched = patched_cves(paths, project)
    lines: dict[tuple[str, str, str], str] = {}
    for decision in scan.decisions:
        for f in decision.findings:
            listed = _listed(f, paranoid=meta.posture is Posture.PARANOID, patched=patched,
                             stale_listed=stale_listed, stale=stale)
            if listed is not None:
                lines.setdefault((f.finding.cve_id, f.finding.package, decision.image_ref),
                                 _line(f, decision.image_ref,
                                       ", ".join(services[decision.image_ref]), listed))
    return list(lines.values())


def _catalog_lines(paths: BoxPaths, project: str, kev: KevCatalog, stale: str) -> list[str]:
    """With no usable CISA catalog nothing at all can be checked: refused
    unless prod-deploy's --accept-stale-kev accepts it. A stale one that is
    cached is judged finding by finding (_cve_lines); the gap is warned."""
    if kev.unreadable is None and kev.fetched_at is not None:
        print(f"  WARNING: the CISA KEV catalog is stale ({stale}): CVEs CISA listed since "
              f"{kev.fetched_at.date().isoformat()} could not be checked.")
        return []
    refusal = (f"there is no usable CISA KEV catalog ({stale}), so boxmunge cannot tell "
               f"whether anything in the release's images is actively exploited")
    if accept_at_guard(project, KevLiftCheck(stale, refusal=refusal, acceptable=True),
                       paths) is not None:
        return []
    exit_ = stale_exit(project, paths)  # prod-deploy's narrower exit comes first
    return [refusal[0].upper() + refusal[1:] + ".", f"{fresh_data_advice()}; then deploy again.",
            *([exit_] if exit_ else [])]


def _problems(paths: BoxPaths, target: ReleaseTarget,
              manifest: dict[str, Any]) -> tuple[list[str], bool]:
    """(what refuses the release, whether any of it is a CVE in its images)."""
    project = target.project
    try:
        meta = project_meta(project, manifest, [])
        starts, unnamed = start_images(target)
        kev = load_kev(paths)
        scan, _ids, targets, _profile = scan_release_images(
            paths, target, meta, starts, unnamed, kev)
    except (ScannerError, StateError, OSError, RuntimeError, ComposeResolveError,
            DockerError) as e:
        return [f"The scan of the release's images failed: {e}",
                "boxmunge cannot show the release carries no known-exploited CVE. Fix the "
                "cause and deploy again."], False
    stale = kev.stale_reason(datetime.now(timezone.utc).date())
    cves = _cve_lines(paths, project, meta, scan, targets, kev, stale)
    problems = list(cves)
    if not scan.complete:
        problems += [*scan.incomplete_reasons(),
                     "The scan did not cover every image the release would start, so "
                     "boxmunge cannot show it carries no known-exploited CVE."]
    if stale is not None:
        problems += _catalog_lines(paths, project, kev, stale)
    return problems, bool(cves)


def _let_through(paths: BoxPaths, override: _Override, project: str, where: str,
                 component: str, problems: list[str]) -> None:
    """Deploy past the refusal with the operator's reason: logged and
    alerted once per command (a rollback decides its release twice)."""
    override.consulted = True
    print(f"  WARNING: {OVERRIDE_FLAG}: deploying to {where} although the deploy guard "
          f"refused this release (reason: {override.reason}):")
    for line in problems:
        print(f"    {line}")
    key = tuple(problems)
    if key in override.recorded:
        return
    override.recorded.add(key)
    log_warning(component, f"{OVERRIDE_FLAG}: deploying to {where} past the deploy guard",
                paths, project=project,
                detail={"reason": override.reason, "where": where, "problems": problems})
    notify(paths, f"{project}: deploying past the deploy guard",
           f"{project}: {OVERRIDE_FLAG} accepted for a release to {where} that the deploy "
           f"guard refused. Reason given: {override.reason}\n" + "\n".join(problems),
           component=component, project=project, priority=0)


def guard_release(paths: BoxPaths, target: ReleaseTarget, manifest: dict[str, Any]) -> None:
    """Scan every image the release would start (built and pulled, not yet
    started) and refuse it when it carries a known-exploited CVE. Raises
    SecurityRegressionRefused, unless this command's
    --allow-security-regression lets it through."""
    project = target.project
    where = "staging" if target.staging else "production"
    component = "stage" if target.staging else "deploy"
    print("  Deploy guard: scanning the release's images for known-exploited CVEs...")
    problems, carries_cve = _problems(paths, target, manifest)
    override = _CURRENT.get()
    if override is not None:
        if override.project != project:
            raise RuntimeError(f"{OVERRIDE_FLAG} was given for {override.project}, "
                               f"not {project}")
        override.checked = True
    if not problems:
        print("  Deploy guard: no known-exploited CVE in the release's images.")
        return
    if override is None or override.reason is None:
        header = ("This release carries a known-exploited CVE" if carries_cve
                  else "The deploy guard could not clear this release")
        raise SecurityRegressionRefused([f"{header}; nothing was started in {where}:",
                                         *problems],
                                        FIX_IN_REPO if carries_cve else DEPLOY_ANYWAY)
    _let_through(paths, override, project, where, component, problems)
