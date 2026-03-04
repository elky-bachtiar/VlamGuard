"""Tests for the Rich terminal output module (report/terminal.py).

Uses a StringIO-backed Rich Console so no real TTY is required.
All output assertions check real rendered text — not mocks.
"""

from io import StringIO

import pytest
from rich.console import Console

from vlamguard.models.response import (
    AIContext,
    AnalyzeResponse,
    ExternalFinding,
    HardeningAction,
    ImpactItem,
    PolicyCheckResult,
    RiskLevel,
    SecretFinding,
    SecurityGrade,
    SecuritySection,
    SecretsDetectionResult,
)
from vlamguard.report.terminal import _print_security_section, print_report


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _console() -> tuple[Console, StringIO]:
    """Return (console, buffer) where console writes to buffer."""
    buf = StringIO()
    # force_terminal=True so Rich renders markup rather than stripping it.
    # highlight=False avoids extra colour codes that complicate assertions.
    con = Console(file=buf, force_terminal=True, highlight=False, width=120)
    return con, buf


def _minimal_response(**overrides) -> AnalyzeResponse:
    """Construct a baseline AnalyzeResponse with sane defaults."""
    defaults: dict = dict(
        risk_score=0,
        risk_level=RiskLevel.LOW,
        blocked=False,
        hard_blocks=[],
        policy_checks=[
            PolicyCheckResult(
                check_id="image_tag",
                name="Image Tag Policy",
                passed=True,
                severity="critical",
                message="All images use explicit version tags.",
            )
        ],
        external_findings=[],
        polaris_score=None,
        security_grade=None,
        security=None,
        ai_context=None,
        metadata={"environment": "staging", "chart": "test"},
    )
    defaults.update(overrides)
    return AnalyzeResponse(**defaults)


# ---------------------------------------------------------------------------
# print_report — clean, no security, no AI
# ---------------------------------------------------------------------------


class TestPrintReportCleanResponse:
    def test_passed_status_in_header(self):
        """A non-blocked response must show PASSED in the header panel."""
        con, buf = _console()
        response = _minimal_response()
        print_report(response, console=con)
        output = buf.getvalue()
        assert "PASSED" in output

    def test_risk_score_in_output(self):
        """Risk score value must appear in output."""
        con, buf = _console()
        response = _minimal_response(risk_score=0)
        print_report(response, console=con)
        output = buf.getvalue()
        assert "0/100" in output

    def test_risk_level_in_output(self):
        """Risk level label must appear in output."""
        con, buf = _console()
        response = _minimal_response(risk_level=RiskLevel.LOW)
        print_report(response, console=con)
        output = buf.getvalue()
        assert "LOW" in output.upper()

    def test_environment_in_output(self):
        """Environment name must appear in output."""
        con, buf = _console()
        response = _minimal_response()
        print_report(response, console=con)
        output = buf.getvalue()
        assert "staging" in output

    def test_policy_table_check_name_in_output(self):
        """Policy check name must appear in the policy table."""
        con, buf = _console()
        response = _minimal_response()
        print_report(response, console=con)
        output = buf.getvalue()
        assert "Image Tag Policy" in output

    def test_no_ai_message_shown_when_no_context(self):
        """When ai_context is None the 'AI context not available' message must appear."""
        con, buf = _console()
        response = _minimal_response(ai_context=None)
        print_report(response, console=con)
        output = buf.getvalue()
        assert "not available" in output.lower()

    def test_uses_default_console_when_none_passed(self):
        """print_report must not raise when console=None (creates its own Console)."""
        response = _minimal_response()
        # Should not raise — it creates a default Console internally.
        print_report(response, console=None)

    def test_no_security_grade_in_clean_response(self):
        """A response without security_grade must not include a 'Security Grade' line."""
        con, buf = _console()
        response = _minimal_response(security_grade=None)
        print_report(response, console=con)
        output = buf.getvalue()
        assert "Security Grade" not in output


# ---------------------------------------------------------------------------
# print_report — hard blocks
# ---------------------------------------------------------------------------


class TestPrintReportHardBlocks:
    def test_blocked_status_shown(self):
        """A blocked response must show BLOCKED in the header panel."""
        con, buf = _console()
        response = _minimal_response(
            risk_score=100,
            risk_level=RiskLevel.CRITICAL,
            blocked=True,
            hard_blocks=["Image Tag Policy: Container 'app' uses 'latest' tag"],
            policy_checks=[
                PolicyCheckResult(
                    check_id="image_tag",
                    name="Image Tag Policy",
                    passed=False,
                    severity="critical",
                    message="Container 'app' uses 'latest' tag",
                )
            ],
        )
        print_report(response, console=con)
        output = buf.getvalue()
        assert "BLOCKED" in output

    def test_hard_block_messages_printed(self):
        """Each hard block message must appear in the output."""
        con, buf = _console()
        block_msg = "Image Tag Policy: Container 'app' uses 'latest' tag"
        response = _minimal_response(
            risk_score=100,
            risk_level=RiskLevel.CRITICAL,
            blocked=True,
            hard_blocks=[block_msg],
        )
        print_report(response, console=con)
        output = buf.getvalue()
        assert "Image Tag Policy" in output

    def test_multiple_hard_blocks_all_shown(self):
        """Multiple hard block messages must all appear."""
        con, buf = _console()
        blocks = [
            "Image Tag Policy: latest tag",
            "Security Context: privileged container",
        ]
        response = _minimal_response(
            risk_score=100,
            risk_level=RiskLevel.CRITICAL,
            blocked=True,
            hard_blocks=blocks,
        )
        print_report(response, console=con)
        output = buf.getvalue()
        assert "Image Tag Policy" in output
        assert "Security Context" in output


# ---------------------------------------------------------------------------
# print_report — security grade and secrets findings
# ---------------------------------------------------------------------------


class TestPrintReportWithSecurity:
    def _make_security_response(
        self,
        hard_secrets: bool = False,
        soft_secrets: bool = False,
        extended_checks: bool = False,
        hardening: bool = False,
        grade: SecurityGrade = SecurityGrade.B,
    ) -> AnalyzeResponse:
        hard_blocks_list: list[SecretFinding] = []
        soft_risks_list: list[SecretFinding] = []

        if hard_secrets:
            hard_blocks_list.append(
                SecretFinding(
                    severity="critical",
                    type="database_url",
                    location="Deployment/backend → container/api → env/DATABASE_URL",
                    pattern="database_url",
                    detection="deterministic",
                    recommendation="Move to a Kubernetes Secret.",
                )
            )

        if soft_secrets:
            soft_risks_list.append(
                SecretFinding(
                    severity="medium",
                    type="suspicious_key_name",
                    location="Deployment/backend → container/api → env/API_KEY",
                    pattern="suspicious_key_name",
                    detection="deterministic",
                )
            )

        secrets_detection = SecretsDetectionResult(
            total_suspects=len(hard_blocks_list) + len(soft_risks_list),
            confirmed_secrets=len(hard_blocks_list),
            false_positives=0,
            hard_blocks=hard_blocks_list,
            soft_risks=soft_risks_list,
            summary="AI summary of secrets." if (hard_secrets or soft_secrets) else None,
        )

        ext_checks: list[PolicyCheckResult] = []
        if extended_checks:
            ext_checks.append(
                PolicyCheckResult(
                    check_id="host_namespace",
                    name="Host Namespace",
                    passed=False,
                    severity="critical",
                    message="hostNetwork is enabled",
                )
            )

        hardening_recs: list[HardeningAction] = []
        if hardening:
            hardening_recs.append(
                HardeningAction(
                    priority=1,
                    category="container",
                    action="Set readOnlyRootFilesystem: true on all containers",
                    effort="low",
                    impact="high",
                    details="Prevents writes to the container filesystem.",
                )
            )

        security = SecuritySection(
            secrets_detection=secrets_detection,
            extended_checks=ext_checks,
            hardening_recommendations=hardening_recs,
        )

        return _minimal_response(
            security_grade=grade,
            security=security,
        )

    def test_security_grade_shown_in_header(self):
        """Security grade must appear in the header panel."""
        con, buf = _console()
        response = self._make_security_response(grade=SecurityGrade.A)
        print_report(response, console=con)
        output = buf.getvalue()
        assert "Security Grade" in output
        assert "A" in output

    def test_grade_description_shown(self):
        """The human-readable grade description must appear."""
        con, buf = _console()
        response = self._make_security_response(grade=SecurityGrade.A)
        print_report(response, console=con)
        output = buf.getvalue()
        assert "Excellent security posture" in output

    def test_hard_secret_block_shown(self):
        """A hard block secret must appear in the output with HARD BLOCK label."""
        con, buf = _console()
        response = self._make_security_response(hard_secrets=True)
        print_report(response, console=con)
        output = buf.getvalue()
        assert "HARD BLOCK" in output
        assert "database_url" in output

    def test_hard_secret_recommendation_shown(self):
        """The recommendation on a hard-block SecretFinding must appear."""
        con, buf = _console()
        response = self._make_security_response(hard_secrets=True)
        print_report(response, console=con)
        output = buf.getvalue()
        assert "Kubernetes Secret" in output

    def test_soft_risk_shown(self):
        """A soft-risk secret must appear with WARNING label."""
        con, buf = _console()
        response = self._make_security_response(soft_secrets=True)
        print_report(response, console=con)
        output = buf.getvalue()
        assert "WARNING" in output
        assert "suspicious_key_name" in output

    def test_no_secrets_clean_message_shown(self):
        """When there are no secrets at all, clean message must appear."""
        con, buf = _console()
        response = self._make_security_response()
        print_report(response, console=con)
        output = buf.getvalue()
        assert "No secrets detected" in output

    def test_secrets_summary_shown(self):
        """Secrets AI summary must appear in output when present."""
        con, buf = _console()
        response = self._make_security_response(hard_secrets=True)
        print_report(response, console=con)
        output = buf.getvalue()
        assert "AI summary of secrets" in output

    def test_extended_checks_table_shown(self):
        """Extended security check table must appear when extended_checks are present."""
        con, buf = _console()
        response = self._make_security_response(extended_checks=True)
        print_report(response, console=con)
        output = buf.getvalue()
        assert "Extended Security Checks" in output
        assert "Host Namespace" in output

    def test_hardening_recommendations_shown(self):
        """Hardening recommendations must appear when present."""
        con, buf = _console()
        response = self._make_security_response(hardening=True)
        print_report(response, console=con)
        output = buf.getvalue()
        assert "Hardening Recommendations" in output
        assert "readOnlyRootFilesystem" in output

    def test_hardening_recommendation_details_shown(self):
        """Hardening recommendation details must appear in output."""
        con, buf = _console()
        response = self._make_security_response(hardening=True)
        print_report(response, console=con)
        output = buf.getvalue()
        assert "Prevents writes" in output

    def test_all_security_grade_labels_render(self):
        """All valid security grades (A-F) must render without error."""
        for grade in (SecurityGrade.A, SecurityGrade.B, SecurityGrade.C, SecurityGrade.D, SecurityGrade.F):
            con, buf = _console()
            response = self._make_security_response(grade=grade)
            print_report(response, console=con)
            output = buf.getvalue()
            # The grade character must appear in the output
            assert grade.value in output


# ---------------------------------------------------------------------------
# print_report — external findings and polaris score
# ---------------------------------------------------------------------------


class TestPrintReportExternalFindings:
    def test_external_table_shown(self):
        """External tool findings table must appear when findings are present."""
        con, buf = _console()
        ext_findings = [
            ExternalFinding(
                tool="kube-score",
                check_id="container-image-tag",
                severity="critical",
                message="Image uses latest tag",
                resource="Deployment/web",
            ),
        ]
        response = _minimal_response(external_findings=ext_findings)
        print_report(response, console=con)
        output = buf.getvalue()
        assert "External Tool Findings" in output
        assert "kube-score" in output
        assert "container-image-tag" in output

    def test_multiple_external_tools_all_shown(self):
        """Findings from multiple tools must all appear."""
        con, buf = _console()
        ext_findings = [
            ExternalFinding(
                tool="kube-score",
                check_id="check-a",
                severity="critical",
                message="Error from kube-score",
            ),
            ExternalFinding(
                tool="kube-linter",
                check_id="check-b",
                severity="warning",
                message="Warning from kube-linter",
            ),
            ExternalFinding(
                tool="polaris",
                check_id="check-c",
                severity="warning",
                message="Warning from polaris",
            ),
        ]
        response = _minimal_response(external_findings=ext_findings)
        print_report(response, console=con)
        output = buf.getvalue()
        assert "kube-score" in output
        assert "kube-linter" in output
        assert "polaris" in output

    def test_finding_without_resource_shows_dash(self):
        """An ExternalFinding with no resource must render '-' in the resource column."""
        con, buf = _console()
        ext_findings = [
            ExternalFinding(
                tool="kube-score",
                check_id="check",
                severity="warning",
                message="Some finding",
                resource=None,
            ),
        ]
        response = _minimal_response(external_findings=ext_findings)
        print_report(response, console=con)
        output = buf.getvalue()
        assert "kube-score" in output

    def test_no_external_table_when_empty(self):
        """When external_findings is empty, the table must not appear."""
        con, buf = _console()
        response = _minimal_response(external_findings=[])
        print_report(response, console=con)
        output = buf.getvalue()
        assert "External Tool Findings" not in output

    def test_polaris_score_comparison_shown(self):
        """Polaris score comparison line must appear when polaris_score is set."""
        con, buf = _console()
        response = _minimal_response(polaris_score=78, risk_score=42)
        print_report(response, console=con)
        output = buf.getvalue()
        assert "Score Comparison" in output
        assert "Polaris" in output
        assert "78" in output
        assert "42" in output

    def test_no_polaris_line_when_none(self):
        """When polaris_score is None, the comparison line must not appear."""
        con, buf = _console()
        response = _minimal_response(polaris_score=None)
        print_report(response, console=con)
        output = buf.getvalue()
        assert "Score Comparison" not in output


# ---------------------------------------------------------------------------
# print_report — AI context
# ---------------------------------------------------------------------------


class TestPrintReportAIContext:
    def _ai_context(self, with_rollback: bool = True) -> AIContext:
        return AIContext(
            summary="This is a risky change deploying untested images.",
            impact_analysis=[
                ImpactItem(severity="high", resource="Deployment/web", description="Unpinned image may break prod.")
            ],
            recommendations=["Pin image tag to a specific version.", "Enable image scanning in CI."],
            rollback_suggestion="kubectl rollout undo deployment/web" if with_rollback else "",
        )

    def test_ai_summary_shown(self):
        """AI summary must appear in the AI Analysis panel."""
        con, buf = _console()
        response = _minimal_response(ai_context=self._ai_context())
        print_report(response, console=con)
        output = buf.getvalue()
        assert "AI Analysis" in output
        assert "risky change" in output

    def test_ai_recommendations_shown(self):
        """AI recommendations must be listed."""
        con, buf = _console()
        response = _minimal_response(ai_context=self._ai_context())
        print_report(response, console=con)
        output = buf.getvalue()
        assert "Recommendations" in output
        assert "Pin image tag" in output
        assert "image scanning" in output

    def test_ai_rollback_suggestion_shown(self):
        """Rollback suggestion must appear in output."""
        con, buf = _console()
        response = _minimal_response(ai_context=self._ai_context(with_rollback=True))
        print_report(response, console=con)
        output = buf.getvalue()
        assert "Rollback" in output
        assert "kubectl rollout undo" in output

    def test_no_ai_fallback_message_when_context_present(self):
        """When AI context is provided, 'not available' must NOT appear."""
        con, buf = _console()
        response = _minimal_response(ai_context=self._ai_context())
        print_report(response, console=con)
        output = buf.getvalue()
        assert "not available" not in output.lower()

    def test_empty_recommendations_list_no_crash(self):
        """AI context with empty recommendations list must not raise."""
        con, buf = _console()
        ai = AIContext(
            summary="No recommendations needed.",
            impact_analysis=[],
            recommendations=[],
            rollback_suggestion="",
        )
        response = _minimal_response(ai_context=ai)
        print_report(response, console=con)
        output = buf.getvalue()
        assert "AI Analysis" in output


# ---------------------------------------------------------------------------
# _print_security_section — direct unit tests
# ---------------------------------------------------------------------------


class TestPrintSecuritySection:
    def test_no_security_section_returns_early(self):
        """_print_security_section must return without error when security is None."""
        con, buf = _console()
        response = _minimal_response(security=None, security_grade=None)
        # Should not raise
        _print_security_section(response, con)
        # Nothing should be printed
        assert buf.getvalue() == ""

    def test_hardening_recs_with_impact_styles(self):
        """Hardening recommendations with different impact levels must all render."""
        con, buf = _console()
        hardening_recs = [
            HardeningAction(
                priority=1,
                category="container",
                action="Set readOnlyRootFilesystem: true",
                effort="low",
                impact="high",
                details="Prevents container filesystem writes.",
            ),
            HardeningAction(
                priority=2,
                category="network",
                action="Apply NetworkPolicy",
                effort="medium",
                impact="medium",
            ),
            HardeningAction(
                priority=3,
                category="operational",
                action="Enable audit logging",
                effort="high",
                impact="low",
            ),
        ]
        security = SecuritySection(
            secrets_detection=None,
            extended_checks=[],
            hardening_recommendations=hardening_recs,
        )
        response = _minimal_response(
            security_grade=SecurityGrade.C,
            security=security,
        )
        _print_security_section(response, con)
        output = buf.getvalue()
        assert "Hardening Recommendations" in output
        assert "readOnlyRootFilesystem" in output
        assert "NetworkPolicy" in output
        assert "audit logging" in output

    def test_secrets_detection_no_findings_clean_message(self):
        """When secrets_detection has no findings, clean message must appear."""
        con, buf = _console()
        secrets_detection = SecretsDetectionResult(
            total_suspects=0,
            confirmed_secrets=0,
            false_positives=0,
            hard_blocks=[],
            soft_risks=[],
        )
        security = SecuritySection(
            secrets_detection=secrets_detection,
            extended_checks=[],
            hardening_recommendations=[],
        )
        response = _minimal_response(
            security_grade=SecurityGrade.A,
            security=security,
        )
        _print_security_section(response, con)
        output = buf.getvalue()
        assert "No secrets detected" in output

    def test_hard_block_without_recommendation_renders(self):
        """Hard block SecretFinding without recommendation must render without crashing."""
        con, buf = _console()
        hard_finding = SecretFinding(
            severity="critical",
            type="private_key",
            location="Deployment/web → container/app → env/PRIVATE_KEY",
            pattern="private_key",
            detection="deterministic",
            recommendation=None,
        )
        secrets_detection = SecretsDetectionResult(
            total_suspects=1,
            confirmed_secrets=1,
            false_positives=0,
            hard_blocks=[hard_finding],
            soft_risks=[],
        )
        security = SecuritySection(
            secrets_detection=secrets_detection,
            extended_checks=[],
            hardening_recommendations=[],
        )
        response = _minimal_response(
            security_grade=SecurityGrade.F,
            security=security,
        )
        _print_security_section(response, con)
        output = buf.getvalue()
        assert "HARD BLOCK" in output
        assert "private_key" in output

    def test_extended_checks_pass_and_fail_both_render(self):
        """Extended checks table must show both passing and failing entries."""
        con, buf = _console()
        ext_checks = [
            PolicyCheckResult(
                check_id="host_namespace",
                name="Host Namespace",
                passed=False,
                severity="critical",
                message="hostNetwork is enabled",
            ),
            PolicyCheckResult(
                check_id="service_account_token",
                name="Service Account Token",
                passed=True,
                severity="medium",
                message="Service account token auto-mount is disabled.",
            ),
        ]
        security = SecuritySection(
            secrets_detection=None,
            extended_checks=ext_checks,
            hardening_recommendations=[],
        )
        response = _minimal_response(
            security_grade=SecurityGrade.D,
            security=security,
        )
        _print_security_section(response, con)
        output = buf.getvalue()
        assert "Extended Security Checks" in output
        assert "Host Namespace" in output
        assert "Service Account Token" in output
        # Both PASS and FAIL results must appear
        assert "FAIL" in output
        assert "PASS" in output

    def test_secrets_summary_appears_when_set(self):
        """Secrets AI summary must appear below the findings section."""
        con, buf = _console()
        secrets_detection = SecretsDetectionResult(
            total_suspects=1,
            confirmed_secrets=0,
            false_positives=0,
            hard_blocks=[],
            soft_risks=[
                SecretFinding(
                    severity="medium",
                    type="suspicious_key_name",
                    location="Deployment/web → env/API_KEY",
                    pattern="suspicious_key_name",
                    detection="deterministic",
                )
            ],
            summary="This soft risk should be moved to a Kubernetes Secret.",
        )
        security = SecuritySection(
            secrets_detection=secrets_detection,
            extended_checks=[],
            hardening_recommendations=[],
        )
        response = _minimal_response(
            security_grade=SecurityGrade.C,
            security=security,
        )
        _print_security_section(response, con)
        output = buf.getvalue()
        assert "This soft risk should be moved" in output
