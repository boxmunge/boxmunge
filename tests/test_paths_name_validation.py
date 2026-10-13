# SPDX-License-Identifier: Apache-2.0
"""Every per-project path is derived through a validated project name.

Regression for the v0.11 audit finding A-01: name validation lived only in
the CLI wrappers, so callers that reached run_* functions directly (MCP
tools, TUI) could pass "" or "." and resolve project_dir() to the projects/
directory itself. MCP project_delete then removed every project.
Validation now happens at the single choke point that turns a name into a
path, so no caller can bypass it.
"""
from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from boxmunge.paths import BoxPaths

PER_PROJECT_METHODS = sorted(
    name for name, fn in inspect.getmembers(BoxPaths, inspect.isfunction)
    if name.startswith("project_") or name == "is_project_pre_registered"
)

BAD_NAMES = ["", ".", "..", "../x", "a/b", "/abs", "UPPER", "-lead", "a" * 64, "a b", "x\n"]


def test_per_project_methods_discovered() -> None:
    assert "project_dir" in PER_PROJECT_METHODS
    assert len(PER_PROJECT_METHODS) >= 18, PER_PROJECT_METHODS


@pytest.mark.parametrize("method", PER_PROJECT_METHODS)
@pytest.mark.parametrize("bad", BAD_NAMES, ids=repr)
def test_per_project_path_rejects_invalid_name(tmp_path: Path, method: str, bad: str) -> None:
    paths = BoxPaths(root=tmp_path)
    with pytest.raises(ValueError, match="Invalid project name"):
        getattr(paths, method)(bad)


@pytest.mark.parametrize("method", PER_PROJECT_METHODS)
def test_per_project_path_accepts_valid_name(tmp_path: Path, method: str) -> None:
    paths = BoxPaths(root=tmp_path)
    getattr(paths, method)("my-app-2")


@pytest.mark.parametrize("bad", ["", ".", ".."], ids=repr)
def test_mcp_project_delete_refuses_and_deletes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad: str,
) -> None:
    from boxmunge import mcp_tools

    root = tmp_path / "bm"
    paths = BoxPaths(root=root)
    for d in (paths.projects / "alpha" / "data", paths.state, paths.logs):
        d.mkdir(parents=True)
    (paths.projects / "alpha" / "data" / "keep.txt").write_text("precious")
    monkeypatch.setattr(mcp_tools, "_get_paths", lambda: paths)

    result = mcp_tools._tool_project_delete(bad, yes=True)

    assert result["success"] is False
    assert any("Invalid project name" in m for m in result["messages"])
    assert (paths.projects / "alpha" / "data" / "keep.txt").read_text() == "precious"
