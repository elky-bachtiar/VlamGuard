"""Comprehensive unit tests for the deterministic security grade calculator."""

import pytest

from vlamguard.engine.grading import calculate_security_grade
from vlamguard.models.response import (
    HardeningAction,
    PolicyCheckResult,
    SecretsDetectionResult,
    SecurityGrade,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_check(
    check_id: str,
    passed: bool,
    details: dict | None = None,
) -> PolicyCheckResult:
    """Build a minimal PolicyCheckResult for the given check_id and pass state."""
    return PolicyCheckResult(
        check_id=check_id,
        name=check_id.replace("_", " ").title(),
        passed=passed,
        severity="high",
        message="test message",
        details=details,
    )


def _make_secrets(confirmed: int = 0) -> SecretsDetectionResult:
    """Build a SecretsDetectionResult with the requested confirmed_secrets count."""
    return SecretsDetectionResult(
        total_suspects=confirmed,
        confirmed_secrets=confirmed,
        false_positives=0,
    )


def _make_hardening(count: int, impact: str = "high") -> list[HardeningAction]:
    """Build *count* HardeningAction objects with the specified impact level."""
    return [
        HardeningAction(
            priority=i + 1,
            category="container",
            action=f"Hardening action {i + 1}",
            effort="low",
            impact=impact,
        )
        for i in range(count)
    ]


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class TestSecurityGrade:

    # -----------------------------------------------------------------------
    # Grade F
    # -----------------------------------------------------------------------

    def test_confirmed_secret_in_production_returns_f(self):
        """A confirmed secret in a production environment is an immediate F."""
        result = calculate_security_grade(
            secrets_result=_make_secrets(confirmed=1),
            extended_check_results=[],
            hardening_recommendations=[],
            environment="production",
        )
        assert result == SecurityGrade.F

    def test_multiple_confirmed_secrets_in_production_returns_f(self):
        """Multiple confirmed secrets in production still returns F (not something worse)."""
        result = calculate_security_grade(
            secrets_result=_make_secrets(confirmed=3),
            extended_check_results=[],
            hardening_recommendations=[],
            environment="production",
        )
        assert result == SecurityGrade.F

    def test_host_namespace_and_dangerous_volumes_both_fail_returns_f(self):
        """host_namespace + dangerous_volume_mounts both failing is F regardless of environment."""
        result = calculate_security_grade(
            secrets_result=_make_secrets(confirmed=0),
            extended_check_results=[
                _make_check("host_namespace", passed=False),
                _make_check("dangerous_volume_mounts", passed=False),
            ],
            hardening_recommendations=[],
            environment="staging",
        )
        assert result == SecurityGrade.F

    def test_host_namespace_and_dangerous_volumes_fail_in_production_returns_f(self):
        """The double-failure rule applies in production too."""
        result = calculate_security_grade(
            secrets_result=None,
            extended_check_results=[
                _make_check("host_namespace", passed=False),
                _make_check("dangerous_volume_mounts", passed=False),
            ],
            hardening_recommendations=[],
            environment="production",
        )
        assert result == SecurityGrade.F

    def test_host_namespace_fail_alone_does_not_return_f(self):
        """Only host_namespace failing (without dangerous_volume_mounts) is NOT Grade F."""
        result = calculate_security_grade(
            secrets_result=None,
            extended_check_results=[
                _make_check("host_namespace", passed=False),
                _make_check("dangerous_volume_mounts", passed=True),
            ],
            hardening_recommendations=[],
            environment="production",
        )
        assert result != SecurityGrade.F

    def test_dangerous_volumes_fail_alone_does_not_return_f(self):
        """Only dangerous_volume_mounts failing (without host_namespace) is NOT Grade F."""
        result = calculate_security_grade(
            secrets_result=None,
            extended_check_results=[
                _make_check("host_namespace", passed=True),
                _make_check("dangerous_volume_mounts", passed=False),
            ],
            hardening_recommendations=[],
            environment="production",
        )
        assert result != SecurityGrade.F

    # -----------------------------------------------------------------------
    # Grade D
    # -----------------------------------------------------------------------

    def test_confirmed_secret_in_non_prod_returns_d(self):
        """A confirmed secret outside production is Grade D, not F."""
        result = calculate_security_grade(
            secrets_result=_make_secrets(confirmed=1),
            extended_check_results=[],
            hardening_recommendations=[],
            environment="dev",
        )
        assert result == SecurityGrade.D

    def test_confirmed_secret_in_staging_returns_d(self):
        """staging is treated the same as any non-production environment."""
        result = calculate_security_grade(
            secrets_result=_make_secrets(confirmed=2),
            extended_check_results=[],
            hardening_recommendations=[],
            environment="staging",
        )
        assert result == SecurityGrade.D

    def test_two_extended_checks_fail_returns_d(self):
        """Failing 2 extended checks (service_account_token + exposed_services) → D."""
        result = calculate_security_grade(
            secrets_result=None,
            extended_check_results=[
                _make_check("service_account_token", passed=False),
                _make_check("exposed_services", passed=False),
            ],
            hardening_recommendations=[],
            environment="dev",
        )
        assert result == SecurityGrade.D

    def test_three_extended_checks_fail_returns_d(self):
        """Failing 3 extended checks still returns D (>= 2 threshold)."""
        result = calculate_security_grade(
            secrets_result=None,
            extended_check_results=[
                _make_check("service_account_token", passed=False),
                _make_check("exposed_services", passed=False),
                _make_check("excessive_capabilities", passed=False,
                            details={"violations": ["NET_BIND_SERVICE"]}),
            ],
            hardening_recommendations=[],
            environment="dev",
        )
        assert result == SecurityGrade.D

    def test_excessive_capabilities_sys_admin_returns_d(self):
        """excessive_capabilities failing with SYS_ADMIN in violations → D."""
        result = calculate_security_grade(
            secrets_result=None,
            extended_check_results=[
                _make_check(
                    "excessive_capabilities",
                    passed=False,
                    details={"violations": ["SYS_ADMIN"]},
                ),
            ],
            hardening_recommendations=[],
            environment="dev",
        )
        assert result == SecurityGrade.D

    def test_excessive_capabilities_all_returns_d(self):
        """excessive_capabilities failing with ALL capability → D."""
        result = calculate_security_grade(
            secrets_result=None,
            extended_check_results=[
                _make_check(
                    "excessive_capabilities",
                    passed=False,
                    details={"violations": ["ALL"]},
                ),
            ],
            hardening_recommendations=[],
            environment="production",
        )
        assert result == SecurityGrade.D

    def test_excessive_capabilities_sys_admin_in_multi_violation_list_returns_d(self):
        """SYS_ADMIN anywhere in the violations list triggers D."""
        result = calculate_security_grade(
            secrets_result=None,
            extended_check_results=[
                _make_check(
                    "excessive_capabilities",
                    passed=False,
                    details={"violations": ["NET_BIND_SERVICE", "SYS_ADMIN", "CHOWN"]},
                ),
            ],
            hardening_recommendations=[],
            environment="dev",
        )
        assert result == SecurityGrade.D

    # -----------------------------------------------------------------------
    # Grade C
    # -----------------------------------------------------------------------

    def test_three_high_impact_recs_returns_c(self):
        """Exactly 3 high-impact hardening recommendations → C."""
        result = calculate_security_grade(
            secrets_result=None,
            extended_check_results=[],
            hardening_recommendations=_make_hardening(3, impact="high"),
            environment="production",
        )
        assert result == SecurityGrade.C

    def test_four_high_impact_recs_returns_c(self):
        """More than 3 high-impact hardening recs still returns C (not B or A)."""
        result = calculate_security_grade(
            secrets_result=None,
            extended_check_results=[],
            hardening_recommendations=_make_hardening(5, impact="high"),
            environment="production",
        )
        assert result == SecurityGrade.C

    def test_single_extended_check_failure_returns_c(self):
        """A single extended check failure (not caught by F/D) → C."""
        result = calculate_security_grade(
            secrets_result=None,
            extended_check_results=[
                _make_check("service_account_token", passed=False),
            ],
            hardening_recommendations=[],
            environment="production",
        )
        assert result == SecurityGrade.C

    def test_exposed_services_fail_alone_returns_c(self):
        """exposed_services alone fails → C (only 1 extended failure, below D threshold)."""
        result = calculate_security_grade(
            secrets_result=None,
            extended_check_results=[
                _make_check("exposed_services", passed=False),
            ],
            hardening_recommendations=[],
            environment="production",
        )
        assert result == SecurityGrade.C

    def test_excessive_capabilities_without_sys_admin_or_all_returns_c(self):
        """excessive_capabilities failing with a non-critical capability (e.g. NET_BIND_SERVICE)
        does not trigger the D-level SYS_ADMIN/ALL check, so the single-failure path → C."""
        result = calculate_security_grade(
            secrets_result=None,
            extended_check_results=[
                _make_check(
                    "excessive_capabilities",
                    passed=False,
                    details={"violations": ["NET_BIND_SERVICE"]},
                ),
            ],
            hardening_recommendations=[],
            environment="production",
        )
        assert result == SecurityGrade.C

    def test_excessive_capabilities_no_violations_key_returns_c(self):
        """excessive_capabilities failing with no 'violations' key in details → C (not D)."""
        result = calculate_security_grade(
            secrets_result=None,
            extended_check_results=[
                _make_check(
                    "excessive_capabilities",
                    passed=False,
                    details={},
                ),
            ],
            hardening_recommendations=[],
            environment="dev",
        )
        assert result == SecurityGrade.C

    def test_excessive_capabilities_none_details_returns_c(self):
        """excessive_capabilities failing with details=None → C (not D)."""
        result = calculate_security_grade(
            secrets_result=None,
            extended_check_results=[
                _make_check("excessive_capabilities", passed=False, details=None),
            ],
            hardening_recommendations=[],
            environment="dev",
        )
        assert result == SecurityGrade.C

    # -----------------------------------------------------------------------
    # Grade B
    # -----------------------------------------------------------------------

    def test_one_high_impact_rec_no_secrets_no_failed_checks_returns_b(self):
        """1 high-impact hardening rec, no secrets, no failed checks → B."""
        result = calculate_security_grade(
            secrets_result=None,
            extended_check_results=[],
            hardening_recommendations=_make_hardening(1, impact="high"),
            environment="production",
        )
        assert result == SecurityGrade.B

    def test_two_high_impact_recs_no_secrets_no_failed_checks_returns_b(self):
        """2 high-impact hardening recs, no secrets, no failed checks → B."""
        result = calculate_security_grade(
            secrets_result=None,
            extended_check_results=[],
            hardening_recommendations=_make_hardening(2, impact="high"),
            environment="production",
        )
        assert result == SecurityGrade.B

    def test_two_high_impact_recs_with_zero_secrets_in_dev_returns_b(self):
        """B is environment-agnostic when there are no secrets and 1-2 high-impact recs."""
        result = calculate_security_grade(
            secrets_result=_make_secrets(confirmed=0),
            extended_check_results=[],
            hardening_recommendations=_make_hardening(2, impact="high"),
            environment="dev",
        )
        assert result == SecurityGrade.B

    def test_one_high_impact_rec_with_passing_extended_checks_returns_b(self):
        """All extended checks pass, 1 high-impact rec → B."""
        result = calculate_security_grade(
            secrets_result=None,
            extended_check_results=[
                _make_check("host_namespace", passed=True),
                _make_check("dangerous_volume_mounts", passed=True),
                _make_check("excessive_capabilities", passed=True),
                _make_check("service_account_token", passed=True),
                _make_check("exposed_services", passed=True),
            ],
            hardening_recommendations=_make_hardening(1, impact="high"),
            environment="production",
        )
        assert result == SecurityGrade.B

    # -----------------------------------------------------------------------
    # Grade A
    # -----------------------------------------------------------------------

    def test_all_checks_pass_no_secrets_no_recs_returns_a(self):
        """The ideal scenario: everything passes, no secrets, no recommendations → A."""
        result = calculate_security_grade(
            secrets_result=None,
            extended_check_results=[],
            hardening_recommendations=[],
            environment="production",
        )
        assert result == SecurityGrade.A

    def test_all_checks_pass_no_secrets_one_low_impact_rec_returns_a(self):
        """1 low-impact recommendation is still Grade A territory."""
        result = calculate_security_grade(
            secrets_result=None,
            extended_check_results=[],
            hardening_recommendations=_make_hardening(1, impact="low"),
            environment="production",
        )
        assert result == SecurityGrade.A

    def test_all_pass_with_zero_confirmed_secrets_returns_a(self):
        """SecretsDetectionResult present but with confirmed=0 still qualifies for A."""
        result = calculate_security_grade(
            secrets_result=_make_secrets(confirmed=0),
            extended_check_results=[],
            hardening_recommendations=[],
            environment="production",
        )
        assert result == SecurityGrade.A

    def test_all_pass_no_recs_in_dev_returns_a(self):
        """Grade A is achievable in non-production environments too."""
        result = calculate_security_grade(
            secrets_result=None,
            extended_check_results=[],
            hardening_recommendations=[],
            environment="dev",
        )
        assert result == SecurityGrade.A

    def test_all_pass_with_all_extended_checks_passing_returns_a(self):
        """All 5 extended checks explicitly passing → A (no secrets, no recs)."""
        result = calculate_security_grade(
            secrets_result=None,
            extended_check_results=[
                _make_check("host_namespace", passed=True),
                _make_check("dangerous_volume_mounts", passed=True),
                _make_check("excessive_capabilities", passed=True),
                _make_check("service_account_token", passed=True),
                _make_check("exposed_services", passed=True),
            ],
            hardening_recommendations=[],
            environment="production",
        )
        assert result == SecurityGrade.A

    # -----------------------------------------------------------------------
    # Grade A boundary — cases that must NOT return A
    # -----------------------------------------------------------------------

    def test_two_low_impact_recs_does_not_return_a(self):
        """Two low-impact recommendations exceed the <=1 threshold, so NOT Grade A."""
        result = calculate_security_grade(
            secrets_result=None,
            extended_check_results=[],
            hardening_recommendations=_make_hardening(2, impact="low"),
            environment="production",
        )
        assert result != SecurityGrade.A

    def test_one_high_impact_rec_does_not_return_a(self):
        """Even a single high-impact recommendation disqualifies Grade A."""
        result = calculate_security_grade(
            secrets_result=None,
            extended_check_results=[],
            hardening_recommendations=_make_hardening(1, impact="high"),
            environment="production",
        )
        assert result != SecurityGrade.A

    # -----------------------------------------------------------------------
    # secrets_result=None edge cases
    # -----------------------------------------------------------------------

    def test_none_secrets_result_does_not_raise(self):
        """None secrets_result is valid; confirmed_secrets defaults to 0."""
        result = calculate_security_grade(
            secrets_result=None,
            extended_check_results=[],
            hardening_recommendations=[],
            environment="production",
        )
        # With nothing bad present, should reach A
        assert result == SecurityGrade.A

    def test_none_secrets_result_in_non_prod_does_not_raise(self):
        """None secrets_result in non-prod also handled without error."""
        result = calculate_security_grade(
            secrets_result=None,
            extended_check_results=[],
            hardening_recommendations=[],
            environment="dev",
        )
        assert result == SecurityGrade.A

    # -----------------------------------------------------------------------
    # Non-extended check IDs are ignored
    # -----------------------------------------------------------------------

    def test_non_extended_check_failure_does_not_affect_grade(self):
        """Failing a check with an ID outside _EXTENDED_CHECK_IDS has no impact on grade."""
        result = calculate_security_grade(
            secrets_result=None,
            extended_check_results=[
                _make_check("image_tag", passed=False),
                _make_check("resource_limits", passed=False),
            ],
            hardening_recommendations=[],
            environment="production",
        )
        # Neither of these are extended checks; no recs → Grade A
        assert result == SecurityGrade.A

    def test_mixed_extended_and_non_extended_failures_only_counts_extended(self):
        """Only extended check IDs count toward the D/C thresholds."""
        result = calculate_security_grade(
            secrets_result=None,
            extended_check_results=[
                _make_check("image_tag", passed=False),       # not extended
                _make_check("resource_limits", passed=False), # not extended
                _make_check("service_account_token", passed=False),  # extended: 1 failure → C
            ],
            hardening_recommendations=[],
            environment="production",
        )
        # Only 1 extended failure → C (not D, not A/B)
        assert result == SecurityGrade.C

    # -----------------------------------------------------------------------
    # Interaction / cascade ordering
    # -----------------------------------------------------------------------

    def test_production_secret_overrides_extended_check_failures(self):
        """F from production secret is returned before any extended-check D/C evaluation."""
        result = calculate_security_grade(
            secrets_result=_make_secrets(confirmed=1),
            extended_check_results=[
                _make_check("service_account_token", passed=False),
                _make_check("exposed_services", passed=False),
            ],
            hardening_recommendations=_make_hardening(5, impact="high"),
            environment="production",
        )
        assert result == SecurityGrade.F

    def test_host_namespace_double_failure_overrides_non_prod_secret_for_f(self):
        """The dual host_namespace+dangerous_volume_mounts failure always returns F,
        even though a non-prod secret would otherwise produce D."""
        result = calculate_security_grade(
            secrets_result=_make_secrets(confirmed=1),
            extended_check_results=[
                _make_check("host_namespace", passed=False),
                _make_check("dangerous_volume_mounts", passed=False),
            ],
            hardening_recommendations=[],
            environment="dev",
        )
        # Production-secret check fires first (is_production=False, so no F from secrets).
        # Then double-failure check fires → F.
        assert result == SecurityGrade.F

    def test_non_prod_secret_takes_priority_over_high_impact_recs(self):
        """D from non-prod secret takes priority over the C from 3+ high-impact recs."""
        result = calculate_security_grade(
            secrets_result=_make_secrets(confirmed=1),
            extended_check_results=[],
            hardening_recommendations=_make_hardening(5, impact="high"),
            environment="staging",
        )
        assert result == SecurityGrade.D

    def test_two_extended_failures_takes_priority_over_high_impact_recs(self):
        """D from >=2 extended failures takes priority over C from 3+ high-impact recs."""
        result = calculate_security_grade(
            secrets_result=None,
            extended_check_results=[
                _make_check("service_account_token", passed=False),
                _make_check("exposed_services", passed=False),
            ],
            hardening_recommendations=_make_hardening(4, impact="high"),
            environment="production",
        )
        assert result == SecurityGrade.D

    def test_grade_f_not_downgraded_by_hardening_recs(self):
        """Grade F is always returned even when there are many hardening recommendations."""
        result = calculate_security_grade(
            secrets_result=_make_secrets(confirmed=1),
            extended_check_results=[],
            hardening_recommendations=_make_hardening(10, impact="high"),
            environment="production",
        )
        assert result == SecurityGrade.F
