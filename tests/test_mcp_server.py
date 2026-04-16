# SPDX-License-Identifier: Apache-2.0
"""Tests for MCP server utilities — stdout capture, result formatting, and tool registrations."""

from unittest.mock import patch

from boxmunge.mcp_tools import capture_tool_call


class TestCaptureToolCall:
    def test_captures_stdout(self) -> None:
        def my_func() -> int:
            print("hello")
            print("world")
            return 0

        result = capture_tool_call(my_func)
        assert result["success"] is True
        assert result["exit_code"] == 0
        assert result["messages"] == ["hello", "world"]
        assert result["data"] == {}

    def test_failure_exit_code(self) -> None:
        def my_func() -> int:
            print("something failed")
            return 1

        result = capture_tool_call(my_func)
        assert result["success"] is False
        assert result["exit_code"] == 1
        assert result["messages"] == ["something failed"]

    def test_exception_returns_failure(self) -> None:
        def my_func() -> int:
            raise RuntimeError("boom")

        result = capture_tool_call(my_func)
        assert result["success"] is False
        assert result["exit_code"] == 1
        assert any("boom" in m for m in result["messages"])

    def test_with_data(self) -> None:
        def my_func() -> int:
            print("done")
            return 0

        result = capture_tool_call(my_func, data={"count": 42})
        assert result["data"] == {"count": 42}
        assert result["success"] is True

    def test_empty_stdout(self) -> None:
        def my_func() -> int:
            return 0

        result = capture_tool_call(my_func)
        assert result["messages"] == []
        assert result["success"] is True


class TestToolRegistration:
    """Test that _tool_* wrappers correctly delegate to run_* functions."""

    def test_deploy_tool_calls_run_deploy(self) -> None:
        from boxmunge.mcp_tools import _tool_deploy
        with patch("boxmunge.commands.deploy.run_deploy") as mock:
            mock.return_value = 0
            result = _tool_deploy("myapp")
        assert result["success"] is True
        mock.assert_called_once()

    def test_deploy_tool_passes_all_args(self) -> None:
        from boxmunge.mcp_tools import _tool_deploy
        with patch("boxmunge.commands.deploy.run_deploy") as mock:
            mock.return_value = 0
            _tool_deploy("myapp", ref="v1.2", no_snapshot=True, dry_run=True)
        args, kwargs = mock.call_args
        assert args[0] == "myapp"
        assert kwargs["ref"] == "v1.2"
        assert kwargs["no_snapshot"] is True
        assert kwargs["dry_run"] is True

    def test_stage_tool_calls_run_stage(self) -> None:
        from boxmunge.mcp_tools import _tool_stage
        with patch("boxmunge.commands.stage_cmd.run_stage") as mock:
            mock.return_value = 0
            result = _tool_stage("myapp")
        assert result["success"] is True
        mock.assert_called_once()

    def test_promote_tool_calls_run_promote(self) -> None:
        from boxmunge.mcp_tools import _tool_promote
        with patch("boxmunge.commands.promote_cmd.run_promote") as mock:
            mock.return_value = 0
            result = _tool_promote("myapp")
        assert result["success"] is True
        mock.assert_called_once()

    def test_unstage_tool_calls_run_unstage(self) -> None:
        from boxmunge.mcp_tools import _tool_unstage
        with patch("boxmunge.commands.unstage_cmd.run_unstage") as mock:
            mock.return_value = 0
            result = _tool_unstage("myapp")
        assert result["success"] is True
        mock.assert_called_once()

    def test_restore_tool_always_passes_yes(self) -> None:
        from boxmunge.mcp_tools import _tool_restore
        with patch("boxmunge.commands.restore.run_restore") as mock:
            mock.return_value = 0
            _tool_restore("myapp")
        call_kwargs = mock.call_args[1]
        assert call_kwargs.get("yes") is True

    def test_rollback_tool_always_passes_yes(self) -> None:
        from boxmunge.mcp_tools import _tool_rollback
        with patch("boxmunge.commands.rollback.run_rollback") as mock:
            mock.return_value = 0
            _tool_rollback("myapp")
        call_kwargs = mock.call_args[1]
        assert call_kwargs.get("yes") is True

    def test_log_tool_returns_entries_in_data(self) -> None:
        from boxmunge.mcp_tools import _tool_log
        with patch("boxmunge.commands.log_cmd.parse_log_file") as mock_parse, \
             patch("boxmunge.commands.log_cmd.filter_log_entries") as mock_filter:
            mock_parse.return_value = []
            mock_filter.return_value = [{"ts": "2026-04-15", "level": "info", "msg": "ok"}]
            result = _tool_log()
        assert result["success"] is True
        assert len(result["data"]["entries"]) == 1

    def test_health_tool_returns_structured_data(self) -> None:
        from boxmunge.mcp_tools import _tool_health
        with patch("boxmunge.mcp_tools._run_health_checks") as mock:
            mock.return_value = (0, {"checks": [{"name": "docker", "status": "ok", "detail": ""}]})
            result = _tool_health()
        assert result["success"] is True
        assert "checks" in result["data"]

    def test_check_tool_calls_run_check(self) -> None:
        from boxmunge.mcp_tools import _tool_check
        with patch("boxmunge.commands.check.run_check") as mock:
            mock.return_value = 0
            result = _tool_check("myapp")
        assert result["success"] is True
        mock.assert_called_once()

    def test_backup_tool_calls_run_backup(self) -> None:
        from boxmunge.mcp_tools import _tool_backup
        with patch("boxmunge.commands.backup_cmd.run_backup") as mock:
            mock.return_value = 0
            result = _tool_backup("myapp")
        assert result["success"] is True
        mock.assert_called_once()

    def test_validate_tool_calls_run_validate(self) -> None:
        from boxmunge.mcp_tools import _tool_validate
        with patch("boxmunge.commands.validate.run_validate") as mock:
            mock.return_value = 0
            result = _tool_validate("myapp")
        assert result["success"] is True
        mock.assert_called_once()

    def test_list_projects_tool(self) -> None:
        from boxmunge.mcp_tools import _tool_list_projects
        with patch("boxmunge.commands.list_projects.run_list_projects") as mock:
            mock.return_value = 0
            result = _tool_list_projects()
        assert result["success"] is True
        mock.assert_called_once()

    def test_status_tool_catches_systemexit(self) -> None:
        from boxmunge.mcp_tools import _tool_status
        with patch("boxmunge.commands.status.cmd_status") as mock:
            mock.side_effect = SystemExit(0)
            result = _tool_status()
        assert result["success"] is True
        assert result["exit_code"] == 0

    def test_failed_tool_returns_failure(self) -> None:
        from boxmunge.mcp_tools import _tool_deploy
        with patch("boxmunge.commands.deploy.run_deploy") as mock:
            mock.return_value = 1
            result = _tool_deploy("myapp")
        assert result["success"] is False
        assert result["exit_code"] == 1


class TestToolDefinitions:
    """Test the _TOOL_DEFS registry."""

    def test_all_tools_have_required_fields(self) -> None:
        from boxmunge.mcp_server import _TOOL_DEFS
        for defn in _TOOL_DEFS:
            assert "name" in defn, f"Missing name in {defn}"
            assert "description" in defn, f"Missing description in {defn}"
            assert "inputSchema" in defn, f"Missing inputSchema in {defn}"
            assert "handler" in defn, f"Missing handler in {defn}"
            assert callable(defn["handler"]), f"Handler not callable for {defn['name']}"

    def test_tool_count(self) -> None:
        from boxmunge.mcp_server import _TOOL_DEFS
        assert len(_TOOL_DEFS) == 18

    def test_unique_tool_names(self) -> None:
        from boxmunge.mcp_server import _TOOL_DEFS
        names = [d["name"] for d in _TOOL_DEFS]
        assert len(names) == len(set(names)), f"Duplicate tool names: {names}"
