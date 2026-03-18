"""Tests for platform detection from git remotes."""

import subprocess
from unittest.mock import patch

import pytest

from vlamguard.integrations import PlatformError
from vlamguard.models.report import Platform, PlatformInfo


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_run_cmd_side_effect(remote_url: str, cli_version: str = "1.0.0"):
    """Return a side_effect function for run_cmd that yields remote URL then CLI version."""
    calls = iter([remote_url, cli_version])

    def _side_effect(args: list[str]) -> str:
        return next(calls)

    return _side_effect


# ---------------------------------------------------------------------------
# Platform override tests
# ---------------------------------------------------------------------------

class TestPlatformOverride:
    def test_override_github_returns_github_platform(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        with patch("vlamguard.integrations.platform.run_cmd") as mock_run:
            mock_run.side_effect = _make_run_cmd_side_effect(
                "https://github.com/org/repo.git"
            )
            info = detect_platform(platform_override="github")
        assert info.platform is Platform.GITHUB

    def test_override_gitlab_returns_gitlab_platform(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        with patch("vlamguard.integrations.platform.run_cmd") as mock_run:
            mock_run.side_effect = _make_run_cmd_side_effect(
                "https://gitlab.com/org/repo.git", cli_version="glab 1.0.0"
            )
            info = detect_platform(platform_override="gitlab")
        assert info.platform is Platform.GITLAB

    def test_override_github_sets_gh_cli_command(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        with patch("vlamguard.integrations.platform.run_cmd") as mock_run:
            mock_run.side_effect = _make_run_cmd_side_effect(
                "https://github.com/org/repo.git"
            )
            info = detect_platform(platform_override="github")
        assert info.cli_command == "gh"

    def test_override_gitlab_sets_glab_cli_command(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        with patch("vlamguard.integrations.platform.run_cmd") as mock_run:
            mock_run.side_effect = _make_run_cmd_side_effect(
                "https://gitlab.com/org/repo.git"
            )
            info = detect_platform(platform_override="gitlab")
        assert info.cli_command == "glab"

    def test_override_github_sets_body_flag(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        with patch("vlamguard.integrations.platform.run_cmd") as mock_run:
            mock_run.side_effect = _make_run_cmd_side_effect(
                "https://github.com/org/repo.git"
            )
            info = detect_platform(platform_override="github")
        assert info.body_flag == "--body"

    def test_override_gitlab_sets_description_flag(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        with patch("vlamguard.integrations.platform.run_cmd") as mock_run:
            mock_run.side_effect = _make_run_cmd_side_effect(
                "https://gitlab.com/org/repo.git"
            )
            info = detect_platform(platform_override="gitlab")
        assert info.body_flag == "--description"

    def test_override_github_term_is_pr(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        with patch("vlamguard.integrations.platform.run_cmd") as mock_run:
            mock_run.side_effect = _make_run_cmd_side_effect(
                "https://github.com/org/repo.git"
            )
            info = detect_platform(platform_override="github")
        assert info.term == "PR"

    def test_override_gitlab_term_is_mr(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        with patch("vlamguard.integrations.platform.run_cmd") as mock_run:
            mock_run.side_effect = _make_run_cmd_side_effect(
                "https://gitlab.com/org/repo.git"
            )
            info = detect_platform(platform_override="gitlab")
        assert info.term == "MR"

    def test_invalid_platform_override_raises_platform_error(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        with patch("vlamguard.integrations.platform.run_cmd") as mock_run:
            mock_run.return_value = "https://github.com/org/repo.git"
            with pytest.raises(PlatformError, match="Invalid platform"):
                detect_platform(platform_override="bitbucket")


# ---------------------------------------------------------------------------
# Auto-detection: HTTPS URLs
# ---------------------------------------------------------------------------

class TestAutoDetectHttps:
    def test_github_https_detected(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        with patch("vlamguard.integrations.platform.run_cmd") as mock_run:
            mock_run.side_effect = _make_run_cmd_side_effect(
                "https://github.com/org/repo.git"
            )
            info = detect_platform()
        assert info.platform is Platform.GITHUB

    def test_gitlab_https_detected(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        with patch("vlamguard.integrations.platform.run_cmd") as mock_run:
            mock_run.side_effect = _make_run_cmd_side_effect(
                "https://gitlab.com/org/repo.git"
            )
            info = detect_platform()
        assert info.platform is Platform.GITLAB

    def test_github_enterprise_https_detected(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        with patch("vlamguard.integrations.platform.run_cmd") as mock_run:
            mock_run.side_effect = _make_run_cmd_side_effect(
                "https://github.mycompany.com/org/repo.git"
            )
            info = detect_platform()
        assert info.platform is Platform.GITHUB

    def test_gitlab_self_hosted_https_detected(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        with patch("vlamguard.integrations.platform.run_cmd") as mock_run:
            mock_run.side_effect = _make_run_cmd_side_effect(
                "https://gitlab.mycompany.com/org/repo.git"
            )
            info = detect_platform()
        assert info.platform is Platform.GITLAB


# ---------------------------------------------------------------------------
# Auto-detection: SSH URLs
# ---------------------------------------------------------------------------

class TestAutoDetectSsh:
    def test_github_ssh_detected(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        with patch("vlamguard.integrations.platform.run_cmd") as mock_run:
            mock_run.side_effect = _make_run_cmd_side_effect(
                "git@github.com:org/repo.git"
            )
            info = detect_platform()
        assert info.platform is Platform.GITHUB

    def test_gitlab_ssh_detected(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        with patch("vlamguard.integrations.platform.run_cmd") as mock_run:
            mock_run.side_effect = _make_run_cmd_side_effect(
                "git@gitlab.com:org/repo.git"
            )
            info = detect_platform()
        assert info.platform is Platform.GITLAB


# ---------------------------------------------------------------------------
# SSH aliases (custom SSH config host aliases)
# ---------------------------------------------------------------------------

class TestSshAliases:
    def test_github_ssh_alias_detected(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        with patch("vlamguard.integrations.platform.run_cmd") as mock_run:
            mock_run.side_effect = _make_run_cmd_side_effect(
                "git@github-elky-bachtiar:org/repo.git"
            )
            info = detect_platform()
        assert info.platform is Platform.GITHUB

    def test_gitlab_ssh_alias_detected(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        with patch("vlamguard.integrations.platform.run_cmd") as mock_run:
            mock_run.side_effect = _make_run_cmd_side_effect(
                "git@gitlab-elky-bachtiar:org/repo.git"
            )
            info = detect_platform()
        assert info.platform is Platform.GITLAB

    def test_github_alias_with_numbers_detected(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        with patch("vlamguard.integrations.platform.run_cmd") as mock_run:
            mock_run.side_effect = _make_run_cmd_side_effect(
                "git@github-user123:org/repo.git"
            )
            info = detect_platform()
        assert info.platform is Platform.GITHUB


# ---------------------------------------------------------------------------
# Custom remote name
# ---------------------------------------------------------------------------

class TestCustomRemote:
    def test_custom_remote_name_used_in_git_command(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        with patch("vlamguard.integrations.platform.run_cmd") as mock_run:
            mock_run.side_effect = _make_run_cmd_side_effect(
                "https://github.com/org/repo.git"
            )
            info = detect_platform(remote="upstream")

        first_call_args = mock_run.call_args_list[0][0][0]
        assert "upstream" in first_call_args

    def test_custom_remote_name_stored_in_platform_info(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        with patch("vlamguard.integrations.platform.run_cmd") as mock_run:
            mock_run.side_effect = _make_run_cmd_side_effect(
                "https://github.com/org/repo.git"
            )
            info = detect_platform(remote="upstream")
        assert info.remote_name == "upstream"

    def test_default_remote_is_origin(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        with patch("vlamguard.integrations.platform.run_cmd") as mock_run:
            mock_run.side_effect = _make_run_cmd_side_effect(
                "https://github.com/org/repo.git"
            )
            info = detect_platform()
        assert info.remote_name == "origin"


# ---------------------------------------------------------------------------
# PlatformInfo field verification
# ---------------------------------------------------------------------------

class TestPlatformInfoFields:
    def test_platform_info_is_pydantic_model(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        with patch("vlamguard.integrations.platform.run_cmd") as mock_run:
            mock_run.side_effect = _make_run_cmd_side_effect(
                "https://github.com/org/repo.git"
            )
            info = detect_platform()
        assert isinstance(info, PlatformInfo)

    def test_remote_url_stored_in_platform_info(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        url = "https://github.com/org/repo.git"
        with patch("vlamguard.integrations.platform.run_cmd") as mock_run:
            mock_run.side_effect = _make_run_cmd_side_effect(url)
            info = detect_platform()
        assert info.remote_url == url

    def test_github_platform_info_all_fields_correct(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        with patch("vlamguard.integrations.platform.run_cmd") as mock_run:
            mock_run.side_effect = _make_run_cmd_side_effect(
                "https://github.com/org/repo.git"
            )
            info = detect_platform()
        assert info.platform is Platform.GITHUB
        assert info.cli_command == "gh"
        assert info.body_flag == "--body"
        assert info.term == "PR"
        assert info.remote_name == "origin"

    def test_gitlab_platform_info_all_fields_correct(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        with patch("vlamguard.integrations.platform.run_cmd") as mock_run:
            mock_run.side_effect = _make_run_cmd_side_effect(
                "https://gitlab.com/org/repo.git"
            )
            info = detect_platform()
        assert info.platform is Platform.GITLAB
        assert info.cli_command == "glab"
        assert info.body_flag == "--description"
        assert info.term == "MR"
        assert info.remote_name == "origin"


# ---------------------------------------------------------------------------
# Error: remote not found
# ---------------------------------------------------------------------------

class TestRemoteNotFoundError:
    def test_missing_remote_raises_platform_error(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        with patch("vlamguard.integrations.platform.run_cmd") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(128, "git")
            with pytest.raises(PlatformError, match="not found"):
                detect_platform()

    def test_missing_remote_error_mentions_remote_name(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        with patch("vlamguard.integrations.platform.run_cmd") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(128, "git")
            with pytest.raises(PlatformError, match="upstream"):
                detect_platform(remote="upstream")

    def test_missing_remote_error_is_platform_error_subclass(self) -> None:
        from vlamguard.integrations.platform import detect_platform
        from vlamguard.integrations import IntegrationError

        with patch("vlamguard.integrations.platform.run_cmd") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(128, "git")
            with pytest.raises(IntegrationError):
                detect_platform()


# ---------------------------------------------------------------------------
# Error: unrecognized URL
# ---------------------------------------------------------------------------

class TestUnrecognizedUrlError:
    def test_bitbucket_url_raises_platform_error(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        with patch("vlamguard.integrations.platform.run_cmd") as mock_run:
            mock_run.return_value = "https://bitbucket.org/org/repo.git"
            with pytest.raises(PlatformError, match="Could not detect platform"):
                detect_platform()

    def test_unknown_host_raises_platform_error(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        with patch("vlamguard.integrations.platform.run_cmd") as mock_run:
            mock_run.return_value = "https://mygit.internal/org/repo.git"
            with pytest.raises(PlatformError, match="Could not detect platform"):
                detect_platform()

    def test_unrecognized_error_mentions_platform_flag(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        with patch("vlamguard.integrations.platform.run_cmd") as mock_run:
            mock_run.return_value = "https://bitbucket.org/org/repo.git"
            with pytest.raises(PlatformError, match="--platform"):
                detect_platform()


# ---------------------------------------------------------------------------
# Error: CLI not installed
# ---------------------------------------------------------------------------

class TestCliNotInstalledError:
    def test_missing_gh_raises_platform_error(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        def _side_effect(args: list[str]) -> str:
            if args[0] == "git":
                return "https://github.com/org/repo.git"
            raise FileNotFoundError("gh not found")

        with patch("vlamguard.integrations.platform.run_cmd", side_effect=_side_effect):
            with pytest.raises(PlatformError, match="not installed"):
                detect_platform()

    def test_missing_glab_raises_platform_error(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        def _side_effect(args: list[str]) -> str:
            if args[0] == "git":
                return "https://gitlab.com/org/repo.git"
            raise FileNotFoundError("glab not found")

        with patch("vlamguard.integrations.platform.run_cmd", side_effect=_side_effect):
            with pytest.raises(PlatformError, match="not installed"):
                detect_platform()

    def test_cli_error_mentions_cli_name(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        def _side_effect(args: list[str]) -> str:
            if args[0] == "git":
                return "https://github.com/org/repo.git"
            raise FileNotFoundError("gh not found")

        with patch("vlamguard.integrations.platform.run_cmd", side_effect=_side_effect):
            with pytest.raises(PlatformError, match="'gh'"):
                detect_platform()

    def test_gh_called_process_error_treated_as_not_installed(self) -> None:
        from vlamguard.integrations.platform import detect_platform

        def _side_effect(args: list[str]) -> str:
            if args[0] == "git":
                return "https://github.com/org/repo.git"
            raise subprocess.CalledProcessError(1, "gh")

        with patch("vlamguard.integrations.platform.run_cmd", side_effect=_side_effect):
            with pytest.raises(PlatformError, match="not installed"):
                detect_platform()
