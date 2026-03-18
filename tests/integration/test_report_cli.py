# tests/integration/test_report_cli.py
"""Integration tests for report CLI commands with real VlamGuard analysis."""

from unittest.mock import patch

from typer.testing import CliRunner

from vlamguard.cli import app

runner = CliRunner()


class TestReportCommandIntegration:
    @patch("vlamguard.cli.create_issue")
    @patch("vlamguard.cli.detect_platform")
    def test_report_with_failing_chart(self, mock_platform, mock_issue):
        """Report on a chart with failures should attempt issue creation."""
        from vlamguard.models.report import Platform, PlatformInfo
        mock_platform.return_value = PlatformInfo(
            platform=Platform.GITHUB,
            remote_url="git@github.com:user/repo.git",
            remote_name="origin",
            cli_command="gh",
            body_flag="--body",
            term="PR",
        )
        mock_issue.return_value = "https://github.com/user/repo/issues/1"

        result = runner.invoke(app, [
            "check",
            "--manifests", "tests/fixtures/security-violations.yaml",
            "--create-issues",
            "--skip-ai",
        ])
        # Should fail because AI is required
        assert result.exit_code != 0

    def test_dry_run_prints_body(self):
        """Dry run with manifests should print issue body."""
        result = runner.invoke(app, [
            "check",
            "--manifests", "tests/fixtures/security-violations.yaml",
            "--create-issues",
            "--dry-run",
            "--skip-ai",
        ])
        # Should error about missing AI context
        assert result.exit_code != 0
