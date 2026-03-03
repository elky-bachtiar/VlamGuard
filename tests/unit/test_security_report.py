"""Tests for security assessment sections in report generation."""

from vlamguard.models.response import (
    AnalyzeResponse,
    HardeningAction,
    PolicyCheckResult,
    RiskLevel,
    SecretFinding,
    SecretsDetectionResult,
    SecurityGrade,
    SecuritySection,
)
from vlamguard.report.generator import generate_markdown


def _make_security_response(
    grade: SecurityGrade = SecurityGrade.C,
    secrets: SecretsDetectionResult | None = None,
    extended_checks: list[PolicyCheckResult] | None = None,
    hardening: list[HardeningAction] | None = None,
) -> AnalyzeResponse:
    if extended_checks is None:
        extended_checks = []
    if hardening is None:
        hardening = []

    return AnalyzeResponse(
        risk_score=30,
        risk_level=RiskLevel.MEDIUM,
        blocked=False,
        hard_blocks=[],
        policy_checks=[],
        security_grade=grade,
        security=SecuritySection(
            secrets_detection=secrets,
            extended_checks=extended_checks,
            hardening_recommendations=hardening,
        ),
        ai_context=None,
        metadata={"environment": "production"},
    )


class TestSecurityReportMarkdown:
    def test_security_grade_displayed(self):
        resp = _make_security_response(grade=SecurityGrade.B)
        md = generate_markdown(resp)
        assert "Security Grade: B" in md
        assert "Good security posture" in md

    def test_grade_f_displayed(self):
        resp = _make_security_response(grade=SecurityGrade.F)
        md = generate_markdown(resp)
        assert "Security Grade: F" in md
        assert "Critical security failures" in md

    def test_secrets_hard_blocks_displayed(self):
        secrets = SecretsDetectionResult(
            total_suspects=1,
            confirmed_secrets=1,
            false_positives=0,
            hard_blocks=[
                SecretFinding(
                    severity="critical",
                    type="database_url",
                    location="Deployment/backend → container/api → env/DATABASE_URL",
                    pattern="database_url",
                    detection="deterministic",
                    recommendation="Use Kubernetes Secrets",
                )
            ],
        )
        resp = _make_security_response(secrets=secrets)
        md = generate_markdown(resp)
        assert "Secrets Detection" in md
        assert "HARD BLOCK" in md
        assert "database_url" in md
        assert "Use Kubernetes Secrets" in md

    def test_secrets_soft_risks_displayed(self):
        secrets = SecretsDetectionResult(
            total_suspects=2,
            confirmed_secrets=0,
            false_positives=0,
            soft_risks=[
                SecretFinding(
                    severity="medium",
                    type="suspicious_key_name",
                    location="Deployment/backend → container/api → env/API_KEY",
                    pattern="suspicious_key_name",
                    detection="deterministic",
                ),
                SecretFinding(
                    severity="medium",
                    type="high_entropy_string",
                    location="ConfigMap/cfg → data/token",
                    pattern="entropy_check",
                    detection="entropy",
                ),
            ],
        )
        resp = _make_security_response(secrets=secrets)
        md = generate_markdown(resp)
        assert "2 soft risk(s)" in md
        assert "entropy" in md

    def test_no_secrets_message(self):
        secrets = SecretsDetectionResult(
            total_suspects=0,
            confirmed_secrets=0,
            false_positives=0,
        )
        resp = _make_security_response(secrets=secrets)
        md = generate_markdown(resp)
        assert "No secrets or credentials detected" in md

    def test_extended_checks_displayed(self):
        checks = [
            PolicyCheckResult(
                check_id="host_namespace",
                name="Host Namespace",
                passed=True,
                severity="critical",
                message="No host namespace sharing.",
            ),
            PolicyCheckResult(
                check_id="excessive_capabilities",
                name="Excessive Capabilities",
                passed=False,
                severity="high",
                message="Container 'api' adds dangerous capabilities: SYS_ADMIN",
            ),
        ]
        resp = _make_security_response(extended_checks=checks)
        md = generate_markdown(resp)
        assert "Extended Security Checks" in md
        assert "PASS Host Namespace" in md
        assert "FAIL Excessive Capabilities" in md

    def test_hardening_recommendations_displayed(self):
        recs = [
            HardeningAction(
                priority=1,
                category="container",
                action="Enable read-only root filesystem",
                effort="low",
                impact="high",
                details="Prevents runtime file modifications",
            ),
        ]
        resp = _make_security_response(hardening=recs)
        md = generate_markdown(resp)
        assert "Hardening Recommendations" in md
        assert "Enable read-only root filesystem" in md
        assert "low effort" in md

    def test_no_security_section_when_none(self):
        resp = AnalyzeResponse(
            risk_score=0,
            risk_level=RiskLevel.LOW,
            blocked=False,
            hard_blocks=[],
            policy_checks=[],
            ai_context=None,
            metadata={"environment": "production"},
        )
        md = generate_markdown(resp)
        assert "Security Assessment" not in md
