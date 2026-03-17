"""Tests for integrations package error hierarchy, get_timeout, and run_cmd."""

import os

import pytest

from vlamguard.integrations import (
    IssueCreationError,
    IntegrationError,
    PRCreationError,
    PlatformError,
    get_timeout,
    run_cmd,
)


class TestErrorHierarchy:
    def test_integration_error_inherits_exception(self) -> None:
        assert issubclass(IntegrationError, Exception)

    def test_platform_error_inherits_integration_error(self) -> None:
        assert issubclass(PlatformError, IntegrationError)

    def test_issue_creation_error_inherits_integration_error(self) -> None:
        assert issubclass(IssueCreationError, IntegrationError)

    def test_pr_creation_error_inherits_integration_error(self) -> None:
        assert issubclass(PRCreationError, IntegrationError)

    def test_platform_error_message_preserved(self) -> None:
        msg = "git remote not found"
        exc = PlatformError(msg)
        assert str(exc) == msg

    def test_issue_creation_error_message_preserved(self) -> None:
        msg = "gh issue create failed with exit code 1"
        exc = IssueCreationError(msg)
        assert str(exc) == msg

    def test_pr_creation_error_message_preserved(self) -> None:
        msg = "working tree is dirty"
        exc = PRCreationError(msg)
        assert str(exc) == msg

    def test_integration_error_is_catchable_as_exception(self) -> None:
        with pytest.raises(Exception):
            raise IntegrationError("base error")

    def test_platform_error_is_catchable_as_integration_error(self) -> None:
        with pytest.raises(IntegrationError):
            raise PlatformError("platform problem")

    def test_issue_creation_error_is_catchable_as_integration_error(self) -> None:
        with pytest.raises(IntegrationError):
            raise IssueCreationError("issue problem")

    def test_pr_creation_error_is_catchable_as_integration_error(self) -> None:
        with pytest.raises(IntegrationError):
            raise PRCreationError("pr problem")


class TestGetTimeout:
    def test_default_timeout_is_60(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("VLAM_INTEGRATION_TIMEOUT", raising=False)
        assert get_timeout() == 60

    def test_custom_timeout_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("VLAM_INTEGRATION_TIMEOUT", "120")
        assert get_timeout() == 120

    def test_invalid_env_falls_back_to_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("VLAM_INTEGRATION_TIMEOUT", "not-a-number")
        assert get_timeout() == 60

    def test_empty_env_falls_back_to_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("VLAM_INTEGRATION_TIMEOUT", "")
        assert get_timeout() == 60

    def test_timeout_returns_int(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("VLAM_INTEGRATION_TIMEOUT", "30")
        result = get_timeout()
        assert isinstance(result, int)


class TestRunCmd:
    def test_run_cmd_is_callable(self) -> None:
        assert callable(run_cmd)

    def test_run_cmd_returns_string_on_success(self) -> None:
        result = run_cmd(["echo", "hello"])
        assert result == "hello"

    def test_run_cmd_strips_trailing_newline(self) -> None:
        result = run_cmd(["echo", "  spaced  "])
        assert result == "spaced"

    def test_run_cmd_raises_on_nonzero_exit(self) -> None:
        import subprocess

        with pytest.raises(subprocess.CalledProcessError):
            run_cmd(["false"])
