"""Tests for risk scoring and gating logic."""

from vlamguard.engine.scoring import RiskResult, calculate_risk
from vlamguard.models.response import PolicyCheckResult, RiskLevel


def _make_check(check_id: str, passed: bool, severity: str = "critical") -> PolicyCheckResult:
    return PolicyCheckResult(
        check_id=check_id, name=check_id, passed=passed, severity=severity, message="test",
    )


class TestRiskScoring:
    def test_all_pass_score_zero(self):
        checks = [
            _make_check("image_tag", True), _make_check("security_context", True),
            _make_check("rbac_scope", True), _make_check("resource_limits", True, "high"),
            _make_check("replica_count", True, "high"),
        ]
        result = calculate_risk(checks, "production")
        assert result.score == 0
        assert result.level == RiskLevel.LOW
        assert result.blocked is False
        assert result.hard_blocks == []

    def test_hard_block_sets_score_100(self):
        checks = [
            _make_check("image_tag", False), _make_check("security_context", True),
            _make_check("rbac_scope", True), _make_check("resource_limits", True, "high"),
            _make_check("replica_count", True, "high"),
        ]
        result = calculate_risk(checks, "production")
        assert result.score == 100
        assert result.blocked is True
        assert len(result.hard_blocks) == 1

    def test_soft_risk_resource_limits_adds_25(self):
        checks = [
            _make_check("image_tag", True), _make_check("security_context", True),
            _make_check("rbac_scope", True), _make_check("resource_limits", False, "high"),
            _make_check("replica_count", True, "high"),
        ]
        result = calculate_risk(checks, "production")
        assert result.score == 25
        assert result.level == RiskLevel.LOW
        assert result.blocked is False

    def test_soft_risk_replica_count_adds_30(self):
        checks = [
            _make_check("image_tag", True), _make_check("security_context", True),
            _make_check("rbac_scope", True), _make_check("resource_limits", True, "high"),
            _make_check("replica_count", False, "high"),
        ]
        result = calculate_risk(checks, "production")
        assert result.score == 30
        assert result.level == RiskLevel.LOW

    def test_both_soft_risks_add_up(self):
        checks = [
            _make_check("image_tag", True), _make_check("security_context", True),
            _make_check("rbac_scope", True), _make_check("resource_limits", False, "high"),
            _make_check("replica_count", False, "high"),
        ]
        result = calculate_risk(checks, "production")
        assert result.score == 55
        assert result.level == RiskLevel.MEDIUM

    def test_dev_environment_critical_fail_is_soft(self):
        checks = [
            _make_check("image_tag", False), _make_check("security_context", True),
            _make_check("rbac_scope", True), _make_check("resource_limits", True, "high"),
            _make_check("replica_count", True, "high"),
        ]
        result = calculate_risk(checks, "dev")
        assert result.blocked is False
        assert result.score > 0

    def test_dev_rbac_still_hard_blocks(self):
        checks = [
            _make_check("image_tag", True), _make_check("security_context", True),
            _make_check("rbac_scope", False), _make_check("resource_limits", True, "high"),
            _make_check("replica_count", True, "high"),
        ]
        result = calculate_risk(checks, "dev")
        assert result.blocked is True
        assert result.score == 100

    def test_score_capped_at_100(self):
        checks = [
            _make_check("image_tag", True), _make_check("security_context", True),
            _make_check("rbac_scope", True), _make_check("resource_limits", False, "high"),
            _make_check("replica_count", False, "high"),
        ]
        result = calculate_risk(checks, "production")
        assert result.score <= 100

    def test_hard_block_level_is_critical(self):
        checks = [
            _make_check("image_tag", False), _make_check("security_context", True),
            _make_check("rbac_scope", True), _make_check("resource_limits", True, "high"),
            _make_check("replica_count", True, "high"),
        ]
        result = calculate_risk(checks, "production")
        assert result.level == RiskLevel.CRITICAL
