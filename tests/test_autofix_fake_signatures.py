# SPDX-License-Identifier: Apache-2.0
"""The test doubles that stand in for the autofix seams take exactly the
parameters of the functions they replace: the same positional parameters,
the same keyword-only names, each optional or required as in the real one.
A double that still took an old signature once hid a required argument the
nightly flow did not pass; this keeps a signature change from hiding behind
a fake again.

recover_interrupted has no double: every test runs the real one."""
from __future__ import annotations

import inspect
from collections.abc import Callable

import pytest

from boxmunge.commands.backup_cmd import backup_locked
from boxmunge.container_recreate import recreate_project, wait_healthy
from boxmunge.cve.autofix_build import build_patched, probe
from boxmunge.cve.autofix_run import autofix_project_locked, repatch_on_upstream_locked
from tests.cve.test_autofix_run import Box as RunnerBox
from tests.test_commands.test_autofix_nightly import Runner as NightlyRunner
from tests.test_commands.test_autofix_upstream import Box as UpstreamBox
from tests.test_commands.test_autofix_urgent import Box as UrgentBox
from tests.test_commands.test_autofix_urgent import Runner as UrgentRunner

_POSITIONAL = (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)

# (the double, as defined on its class, so `self` comes first; the real function)
DOUBLES: list[tuple[Callable, Callable]] = [
    (NightlyRunner.__call__, autofix_project_locked),
    (UrgentRunner.__call__, autofix_project_locked),
    (RunnerBox._build, build_patched),
    (RunnerBox._probe, probe),
    (RunnerBox._recreate, recreate_project),
    (RunnerBox._wait_healthy, wait_healthy),
    (UrgentBox._probe, probe),
    (UpstreamBox._recreate, recreate_project),
    (UpstreamBox._wait_healthy, wait_healthy),
    (UpstreamBox._repatch, repatch_on_upstream_locked),
    (UpstreamBox._backup, backup_locked),
]


def _shape(fn: Callable, *, method: bool) -> tuple[list[bool], dict[str, bool]]:
    """([whether each positional parameter is optional], {keyword-only
    name: whether it is optional}). Raises AssertionError for *args or
    **kwargs, which would accept anything."""
    params = list(inspect.signature(fn).parameters.values())[1 if method else 0:]
    assert all(p.kind not in (p.VAR_POSITIONAL, p.VAR_KEYWORD) for p in params), \
        f"{fn.__qualname__} takes *args or **kwargs"
    optional = [p.default is not p.empty for p in params if p.kind in _POSITIONAL]
    keywords = {p.name: p.default is not p.empty for p in params
                if p.kind is p.KEYWORD_ONLY}
    return optional, keywords


@pytest.mark.parametrize(("double", "real"), DOUBLES,
                         ids=[f"{d.__qualname__}-{r.__name__}" for d, r in DOUBLES])
def test_double_takes_the_real_signature(double, real) -> None:
    assert _shape(double, method=True) == _shape(real, method=False)


def test_a_double_missing_a_required_keyword_is_caught() -> None:
    def real(paths, *, trigger, deadline, quarantined_for_patch): ...

    class Stale:
        def __call__(self, paths, *, trigger, deadline): ...

    assert _shape(Stale.__call__, method=True) != _shape(real, method=False)
