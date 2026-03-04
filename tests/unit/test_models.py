"""Tests for Pydantic request/response models."""

import pytest
from pydantic import ValidationError

from vlamguard.models.request import AnalyzeRequest
from vlamguard.models.response import (
    AIContext,
    AnalyzeResponse,
    HardeningAction,
    ImpactItem,
    PolicyCheckResult,
    Recommendation,
    RiskLevel,
)


class TestAnalyzeRequest:
    def test_valid_request(self):
        req = AnalyzeRequest(
            chart="./my-chart",
            values={"replicaCount": 3},
            environment="production",
        )
        assert req.chart == "./my-chart"
        assert req.environment == "production"
        assert req.threshold is None
        assert req.skip_ai is False

    def test_optional_fields(self):
        req = AnalyzeRequest(
            chart="./chart",
            values={},
            environment="staging",
            threshold=50,
            skip_ai=True,
        )
        assert req.threshold == 50
        assert req.skip_ai is True

    def test_missing_required_fields(self):
        with pytest.raises(ValidationError):
            AnalyzeRequest(chart="./chart", values={})

    def test_threshold_range(self):
        with pytest.raises(ValidationError):
            AnalyzeRequest(
                chart="./chart",
                values={},
                environment="production",
                threshold=101,
            )
        with pytest.raises(ValidationError):
            AnalyzeRequest(
                chart="./chart",
                values={},
                environment="production",
                threshold=-1,
            )


class TestRiskLevel:
    def test_risk_levels_exist(self):
        assert RiskLevel.LOW == "low"
        assert RiskLevel.MEDIUM == "medium"
        assert RiskLevel.HIGH == "high"
        assert RiskLevel.CRITICAL == "critical"


class TestPolicyCheckResult:
    def test_passing_check(self):
        result = PolicyCheckResult(
            check_id="image_tag",
            name="Image Tag Policy",
            passed=True,
            severity="critical",
            message="All images use explicit version tags.",
        )
        assert result.passed is True
        assert result.severity == "critical"

    def test_failing_check(self):
        result = PolicyCheckResult(
            check_id="security_context",
            name="Security Context",
            passed=False,
            severity="critical",
            message="Container runs as root.",
            details={"container": "nginx", "privileged": True},
        )
        assert result.passed is False
        assert result.details["privileged"] is True


class TestAIContext:
    def test_valid_ai_context(self):
        ctx = AIContext(
            summary="Deployment uses latest tag which is risky.",
            impact_analysis=[
                ImpactItem(
                    severity="high",
                    resource="Deployment/nginx",
                    description="Unpinned image may cause unexpected behavior.",
                )
            ],
            recommendations=["Pin image to specific version tag."],
            rollback_suggestion="kubectl rollout undo deployment/nginx",
        )
        assert len(ctx.impact_analysis) == 1
        assert len(ctx.recommendations) == 1


class TestRecommendation:
    def test_structured_recommendation(self):
        rec = Recommendation(
            action="Set runAsNonRoot: true",
            reason="Running as root allows container escape attacks.",
            resource="Deployment/web",
            yaml_snippet="runAsNonRoot: true",
        )
        assert rec.action == "Set runAsNonRoot: true"
        assert rec.reason == "Running as root allows container escape attacks."
        assert rec.resource == "Deployment/web"
        assert rec.yaml_snippet == "runAsNonRoot: true"

    def test_recommendation_action_only(self):
        rec = Recommendation(action="Enable readiness probe")
        assert rec.reason is None
        assert rec.resource is None
        assert rec.yaml_snippet is None

    def test_ai_context_with_mixed_recommendations(self):
        ctx = AIContext(
            summary="Mixed recs.",
            impact_analysis=[],
            recommendations=[
                "Plain string recommendation.",
                Recommendation(action="Set limits", resource="Deployment/api"),
            ],
            rollback_suggestion="kubectl rollout undo",
        )
        assert isinstance(ctx.recommendations[0], str)
        assert isinstance(ctx.recommendations[1], Recommendation)

    def test_hardening_action_with_resource(self):
        ha = HardeningAction(
            priority=1,
            category="container",
            action="Set readOnlyRootFilesystem",
            effort="low",
            impact="high",
            resource="Deployment/web",
            yaml_hint="readOnlyRootFilesystem: true",
        )
        assert ha.resource == "Deployment/web"

    def test_hardening_action_without_resource(self):
        ha = HardeningAction(
            priority=1,
            category="network",
            action="Add NetworkPolicy",
            effort="medium",
            impact="high",
        )
        assert ha.resource is None


class TestAnalyzeResponse:
    def test_full_response(self):
        resp = AnalyzeResponse(
            risk_score=75,
            risk_level=RiskLevel.HIGH,
            blocked=True,
            hard_blocks=["Image Tag Policy: container uses 'latest' tag"],
            policy_checks=[
                PolicyCheckResult(
                    check_id="image_tag",
                    name="Image Tag Policy",
                    passed=False,
                    severity="critical",
                    message="Container uses 'latest' tag.",
                )
            ],
            ai_context=None,
            metadata={"environment": "production", "chart": "nginx"},
        )
        assert resp.blocked is True
        assert resp.risk_score == 75

    def test_risk_score_clamped(self):
        resp = AnalyzeResponse(
            risk_score=100,
            risk_level=RiskLevel.CRITICAL,
            blocked=True,
            hard_blocks=[],
            policy_checks=[],
            ai_context=None,
            metadata={},
        )
        assert resp.risk_score == 100
