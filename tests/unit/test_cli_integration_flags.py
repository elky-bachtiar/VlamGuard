# tests/unit/test_cli_integration_flags.py
"""Tests for --create-issues, --create-pr, --dry-run flags on CLI commands."""

from unittest.mock import patch, AsyncMock

from typer.testing import CliRunner

from vlamguard.cli import app

runner = CliRunner()


class TestCheckCommandIntegrationFlags:
    def test_create_issues_flag_exists(self):
        result = runner.invoke(app, ["check", "--help"])
        assert "--create-issues" in result.output

    def test_create_pr_flag_exists(self):
        result = runner.invoke(app, ["check", "--help"])
        assert "--create-pr" in result.output

    def test_dry_run_flag_exists(self):
        result = runner.invoke(app, ["check", "--help"])
        assert "--dry-run" in result.output

    def test_remote_flag_exists(self):
        result = runner.invoke(app, ["check", "--help"])
        assert "--remote" in result.output

    def test_platform_flag_exists(self):
        result = runner.invoke(app, ["check", "--help"])
        assert "--platform" in result.output


class TestSecurityScanIntegrationFlags:
    def test_create_issues_flag_exists(self):
        result = runner.invoke(app, ["security-scan", "--help"])
        assert "--create-issues" in result.output

    def test_create_pr_flag_exists(self):
        result = runner.invoke(app, ["security-scan", "--help"])
        assert "--create-pr" in result.output


class TestReportCommand:
    def test_report_command_exists(self):
        result = runner.invoke(app, ["report", "--help"])
        assert result.exit_code == 0
        assert "report" in result.output.lower()

    def test_report_has_chart_option(self):
        result = runner.invoke(app, ["report", "--help"])
        assert "--chart" in result.output

    def test_report_requires_chart_or_manifests(self):
        result = runner.invoke(app, ["report"])
        assert result.exit_code != 0


class TestDryRunMode:
    @patch("vlamguard.cli._analyze_manifests", new_callable=AsyncMock)
    @patch("vlamguard.cli._load_manifests")
    def test_dry_run_does_not_create_issue(self, mock_load, mock_analyze):
        """Dry run should print body without calling gh/glab."""
        from vlamguard.models.response import (
            AIContext, AnalyzeResponse, ImpactItem,
            PolicyCheckResult, RiskLevel,
        )

        mock_load.return_value = ([{"kind": "Deployment", "metadata": {"name": "web"}}], "yaml")
        mock_analyze.return_value = AnalyzeResponse(
            risk_score=70,
            risk_level=RiskLevel.HIGH,
            blocked=True,
            hard_blocks=["security_context"],
            policy_checks=[
                PolicyCheckResult(
                    check_id="security_context", name="Security Context",
                    passed=False, severity="critical", message="Missing",
                    category="security",
                ),
            ],
            ai_context=AIContext(
                summary="Test",
                impact_analysis=[],
                recommendations=["Fix it"],
                rollback_suggestion="Rollback",
            ),
            metadata={"environment": "production", "manifest_count": 1},
        )

        with patch("vlamguard.integrations.issues.create_issue") as mock_create:
            result = runner.invoke(app, [
                "check", "--manifests", "tests/fixtures/hardened.yaml",
                "--create-issues", "--dry-run",
            ])
            mock_create.assert_not_called()
