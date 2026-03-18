# tests/unit/test_main_report_endpoint.py
"""Coverage tests for the /api/v1/report endpoint in main.py — lines 44-65."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from vlamguard.integrations import IntegrationError
from vlamguard.main import app
from vlamguard.models.report import Platform, PlatformInfo
from vlamguard.models.response import (
    AIContext,
    AnalyzeResponse,
    PolicyCheckResult,
    RiskLevel,
)

client = TestClient(app)


def _make_analysis(ai_context: AIContext | None = None) -> AnalyzeResponse:
    return AnalyzeResponse(
        risk_score=60,
        risk_level=RiskLevel.HIGH,
        blocked=True,
        hard_blocks=["security_context"],
        policy_checks=[
            PolicyCheckResult(
                check_id="security_context",
                name="Security Context",
                passed=False,
                severity="critical",
                message="Missing security context",
                category="security",
            )
        ],
        ai_context=ai_context or AIContext(
            summary="Issues found.",
            impact_analysis=[],
            recommendations=["Fix it"],
            rollback_suggestion="Rollback.",
        ),
        metadata={"environment": "production", "manifest_count": 1},
    )


def _make_platform() -> PlatformInfo:
    return PlatformInfo(
        platform=Platform.GITHUB,
        remote_url="git@github.com:user/repo.git",
        remote_name="origin",
        cli_command="gh",
        body_flag="--body",
        term="PR",
    )


class TestReportEndpointCreateIssues:
    def test_report_with_create_issues(self):
        analysis = _make_analysis()
        with (
            patch("vlamguard.main.analyze", new_callable=AsyncMock, return_value=analysis),
            patch("vlamguard.main.detect_platform", return_value=_make_platform()),
            patch("vlamguard.main.create_issue", return_value="https://github.com/user/repo/issues/1"),
        ):
            response = client.post(
                "/api/v1/report",
                json={
                    "chart": "./chart",
                    "values": {},
                    "environment": "production",
                    "skip_ai": False,
                    "create_issues": True,
                    "create_pr": False,
                },
            )
        assert response.status_code == 200
        data = response.json()
        assert data["issue_url"] == "https://github.com/user/repo/issues/1"
        assert data["pr_url"] is None


class TestReportEndpointCreatePR:
    def test_report_with_create_pr(self):
        analysis = _make_analysis()
        with (
            patch("vlamguard.main.analyze", new_callable=AsyncMock, return_value=analysis),
            patch("vlamguard.main.detect_platform", return_value=_make_platform()),
            patch("vlamguard.main.create_pull_request", return_value="https://github.com/user/repo/pull/1"),
        ):
            response = client.post(
                "/api/v1/report",
                json={
                    "chart": "./chart",
                    "values": {},
                    "environment": "production",
                    "skip_ai": False,
                    "create_issues": False,
                    "create_pr": True,
                    "manifests_path": "/tmp/values.yaml",
                },
            )
        assert response.status_code == 200
        data = response.json()
        assert data["pr_url"] == "https://github.com/user/repo/pull/1"


class TestReportEndpointCreateBoth:
    def test_report_with_issues_and_pr(self):
        analysis = _make_analysis()
        with (
            patch("vlamguard.main.analyze", new_callable=AsyncMock, return_value=analysis),
            patch("vlamguard.main.detect_platform", return_value=_make_platform()),
            patch("vlamguard.main.create_issue", return_value="https://github.com/user/repo/issues/1"),
            patch("vlamguard.main.create_pull_request", return_value="https://github.com/user/repo/pull/1"),
        ):
            response = client.post(
                "/api/v1/report",
                json={
                    "chart": "./chart",
                    "values": {},
                    "environment": "production",
                    "skip_ai": False,
                    "create_issues": True,
                    "create_pr": True,
                    "manifests_path": "/tmp/values.yaml",
                },
            )
        assert response.status_code == 200
        data = response.json()
        assert data["issue_url"] == "https://github.com/user/repo/issues/1"
        assert data["pr_url"] == "https://github.com/user/repo/pull/1"


class TestReportEndpointIntegrationError:
    def test_integration_error_returns_422(self):
        analysis = _make_analysis()
        with (
            patch("vlamguard.main.analyze", new_callable=AsyncMock, return_value=analysis),
            patch("vlamguard.main.detect_platform", side_effect=IntegrationError("no remote")),
        ):
            response = client.post(
                "/api/v1/report",
                json={
                    "chart": "./chart",
                    "values": {},
                    "environment": "production",
                    "skip_ai": False,
                    "create_issues": True,
                },
            )
        assert response.status_code == 422
        assert "no remote" in response.json()["detail"]

    def test_integration_error_from_create_issue(self):
        analysis = _make_analysis()
        with (
            patch("vlamguard.main.analyze", new_callable=AsyncMock, return_value=analysis),
            patch("vlamguard.main.detect_platform", return_value=_make_platform()),
            patch("vlamguard.main.create_issue", side_effect=IntegrationError("gh not found")),
        ):
            response = client.post(
                "/api/v1/report",
                json={
                    "chart": "./chart",
                    "values": {},
                    "environment": "production",
                    "skip_ai": False,
                    "create_issues": True,
                },
            )
        assert response.status_code == 422
        assert "gh not found" in response.json()["detail"]


class TestReportEndpointNoIntegrations:
    def test_report_without_integrations(self):
        analysis = _make_analysis()
        with patch("vlamguard.main.analyze", new_callable=AsyncMock, return_value=analysis):
            response = client.post(
                "/api/v1/report",
                json={
                    "chart": "./chart",
                    "values": {},
                    "environment": "production",
                    "skip_ai": False,
                },
            )
        assert response.status_code == 200
        data = response.json()
        assert data["issue_url"] is None
        assert data["pr_url"] is None
