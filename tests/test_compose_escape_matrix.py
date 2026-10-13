"""Regression matrix for the v0.11 compose-escape audit (area F).

Each case is a crafted service fragment from the auditor's probe scripts.
The compose file lives where a real project's would — inside
``projects/myapp/`` under the boxmunge root — so relative paths resolve the
way they do on a server.
"""
from __future__ import annotations

from typing import Any

import pytest
import yaml

from boxmunge.compose_validate import ComposeSecurityError, validate_user_compose
from boxmunge.paths import BoxPaths
from boxmunge.security_overlay import SecurityValidationError, validate_security_block


def _validate(paths: BoxPaths, svc: dict[str, Any], top: dict | None = None) -> None:
    doc: dict[str, Any] = {"services": {"web": {"image": "alpine", **svc}}}
    doc.update(top or {})
    project_dir = paths.project_dir("myapp")
    project_dir.mkdir(parents=True, exist_ok=True)
    compose = project_dir / "compose.yml"
    compose.write_text(yaml.safe_dump(doc))
    validate_user_compose(compose, paths, project_name="myapp")


# ---------------------------------------------------------------------------
# F-01 — normalisation, parent paths, strict booleans
# ---------------------------------------------------------------------------

F01_REJECTED = {
    "privileged as string": {"privileged": "true"},
    "read_only as string": {"read_only": "true"},
    "init as string": {"init": "false"},
    "cap CAP_ prefix": {"cap_add": ["CAP_SYS_ADMIN"]},
    "cap lower case": {"cap_add": ["cap_dac_read_search"]},
    "cap padded": {"cap_add": [" sys_admin "]},
    "cap ALL": {"cap_add": ["ALL"]},
    "cap SYS_MODULE": {"cap_add": ["SYS_MODULE"]},
    "cap SYS_RAWIO": {"cap_add": ["SYS_RAWIO"]},
    "cap MAC_ADMIN": {"cap_add": ["MAC_ADMIN"]},
    "nnp with equals": {"security_opt": ["no-new-privileges=false"]},
    "label with equals": {"security_opt": ["label=disable"]},
    "custom seccomp file": {"security_opt": ["seccomp=./allow-all.json"]},
    "custom seccomp colon": {"security_opt": ["seccomp:/srv/allow.json"]},
    "pid padded upper": {"pid": " HOST "},
    "ipc joins container": {"ipc": "container:projb-db-1"},
    "network joins container": {"network_mode": "container:projb-db-1"},
    "uts host": {"uts": "host"},
    "root double slash": {"volumes": ["//:/host"]},
    "root dot": {"volumes": ["/.:/host"]},
    "root via dotdot": {"volumes": ["/tmp/..:/host"]},
    "etc double slash": {"volumes": ["//etc:/h"]},
    "etc via dotdot": {"volumes": ["/tmp/../etc:/h"]},
    "parent of docker.sock": {"volumes": ["/var/run:/h"]},
    "run": {"volumes": ["/run:/h"]},
    "containerd socket": {"volumes": ["/run/containerd/containerd.sock:/c.sock"]},
    "docker state": {"volumes": ["/var/lib/docker:/d"]},
    "root home": {"volumes": ["/root:/r"]},
    "deploy ssh": {"volumes": ["/home/deploy/.ssh:/s"]},
    "boot": {"volumes": ["/boot:/b"]},
    "relative to host root": {"volumes": ["../../../../../../../..:/host"]},
    "relative to boxmunge config": {"volumes": ["../../config:/c"]},
    "relative to projects dir": {"volumes": ["..:/all"]},
    "tilde to root": {"volumes": ["~/../..:/host"]},
    "long bind root": {"volumes": [{"type": "bind", "source": "/", "target": "/h"}]},
    "long bind relative": {
        "volumes": [{"type": "bind", "source": "../../../..", "target": "/h"}],
    },
}


@pytest.mark.parametrize("svc", F01_REJECTED.values(), ids=F01_REJECTED.keys())
def test_f01_hostile_spellings_rejected(paths: BoxPaths, svc: dict) -> None:
    with pytest.raises(ComposeSecurityError):
        _validate(paths, svc)


def test_f01_boxmunge_root_rejected(paths: BoxPaths) -> None:
    with pytest.raises(ComposeSecurityError, match="protected host path"):
        _validate(paths, {"volumes": [f"{paths.root}:/bm"]})


def test_f01_string_flag_error_says_what_to_write(paths: BoxPaths) -> None:
    with pytest.raises(ComposeSecurityError, match="unquoted true or false"):
        _validate(paths, {"privileged": "true"})


F01_ACCEPTED = {
    "lower-case benign cap": {"cap_add": ["net_raw"]},
    "dropped cap re-added": {"cap_add": ["NET_ADMIN", "SYS_PTRACE"]},
    "default seccomp": {"security_opt": ["seccomp=runtime/default"]},
    "named apparmor profile": {"security_opt": ["apparmor=docker-default"]},
    "project data dir": {"volumes": ["./data:/data", "data:/d"]},
    "network via sibling service": {"network_mode": "service:db"},
    "shareable ipc": {"ipc": "shareable"},
    "booleans": {"read_only": False, "init": True, "privileged": False},
}


@pytest.mark.parametrize("svc", F01_ACCEPTED.values(), ids=F01_ACCEPTED.keys())
def test_f01_benign_values_accepted(paths: BoxPaths, svc: dict) -> None:
    _validate(paths, svc)


# Manifest `security.cap_add` shares the compose denylist.

@pytest.mark.parametrize("cap", ["SYS_ADMIN", "DAC_READ_SEARCH", "SYS_MODULE", "BPF", "ALL"])
def test_f01_manifest_cap_add_denylist(cap: str) -> None:
    with pytest.raises(SecurityValidationError, match="never allowed"):
        validate_security_block({"cap_add": [cap]}, "project")


def test_f01_manifest_cap_add_denylist_any_spelling() -> None:
    with pytest.raises(SecurityValidationError, match="never allowed"):
        validate_security_block({"cap_add": ["cap_sys_admin"]}, "service:web")


def test_f01_manifest_cap_requires_canonical_spelling() -> None:
    with pytest.raises(SecurityValidationError, match="'NET_RAW'"):
        validate_security_block({"cap_add": ["cap_net_raw"]}, "project")


def test_f01_manifest_benign_cap_add_accepted() -> None:
    validate_security_block({"cap_add": ["NET_RAW"]}, "project")


def test_f01_manifest_cap_drop_of_denied_cap_accepted() -> None:
    # Dropping a dangerous capability only ever tightens the posture.
    validate_security_block({"cap_drop": ["SYS_ADMIN"]}, "project")
