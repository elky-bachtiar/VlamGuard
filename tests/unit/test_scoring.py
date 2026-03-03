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


class TestSecretsInRiskScoring:
    """Tests for secrets detection integration into risk scoring."""

    def _passing_checks(self) -> list[PolicyCheckResult]:
        return [
            _make_check("image_tag", True),
            _make_check("security_context", True),
            _make_check("rbac_scope", True),
            _make_check("resource_limits", True, "high"),
            _make_check("replica_count", True, "high"),
        ]

    def _secrets_result(self, confirmed: int, hard_blocks: list | None = None, soft_risks: list | None = None):
        from vlamguard.models.response import SecretFinding, SecretsDetectionResult
        hb = hard_blocks or []
        sr = soft_risks or []
        if confirmed > 0 and not hb:
            hb = [
                SecretFinding(
                    severity="critical", type="database_url",
                    location=f"Deployment/backend → container/api → env/DB_URL",
                    pattern="database_url", detection="deterministic",
                )
            ] * confirmed
        return SecretsDetectionResult(
            total_suspects=len(hb) + len(sr),
            confirmed_secrets=len(hb),
            false_positives=0,
            hard_blocks=hb,
            soft_risks=sr,
        )

    def _soft_risk_from_hard_pattern(self, type_name: str = "database_url"):
        from vlamguard.models.response import SecretFinding
        return SecretFinding(
            severity="high", type=type_name,
            location="Deployment/backend → container/api → env/DB_URL",
            pattern=type_name, detection="deterministic",
        )

    def test_production_secret_blocks_deployment(self):
        checks = self._passing_checks()
        secrets = self._secrets_result(confirmed=1)
        result = calculate_risk(checks, "production", secrets_result=secrets)
        assert result.blocked is True

    def test_production_secret_sets_score_100(self):
        checks = self._passing_checks()
        secrets = self._secrets_result(confirmed=1)
        result = calculate_risk(checks, "production", secrets_result=secrets)
        assert result.score == 100

    def test_production_secret_adds_hard_block_message(self):
        checks = self._passing_checks()
        secrets = self._secrets_result(confirmed=1)
        result = calculate_risk(checks, "production", secrets_result=secrets)
        assert any("Secrets Detection" in hb for hb in result.hard_blocks)

    def test_dev_secret_adds_30_to_soft_score(self):
        checks = self._passing_checks()
        sr = [self._soft_risk_from_hard_pattern("database_url")]
        secrets = self._secrets_result(confirmed=0, soft_risks=sr)
        result = calculate_risk(checks, "dev", secrets_result=secrets)
        assert result.score == 30
        assert result.blocked is False

    def test_staging_secret_adds_30(self):
        checks = self._passing_checks()
        sr = [self._soft_risk_from_hard_pattern("database_url")]
        secrets = self._secrets_result(confirmed=0, soft_risks=sr)
        result = calculate_risk(checks, "staging", secrets_result=secrets)
        assert result.score == 30

    def test_multiple_dev_secrets_add_30_each(self):
        checks = self._passing_checks()
        sr = [
            self._soft_risk_from_hard_pattern("database_url"),
            self._soft_risk_from_hard_pattern("aws_access_key"),
        ]
        secrets = self._secrets_result(confirmed=0, soft_risks=sr)
        result = calculate_risk(checks, "dev", secrets_result=secrets)
        assert result.score == 60

    def test_no_secrets_scoring_unchanged(self):
        checks = self._passing_checks()
        result_without = calculate_risk(checks, "production")
        result_with_none = calculate_risk(checks, "production", secrets_result=None)
        assert result_without.score == result_with_none.score
        assert result_without.blocked == result_with_none.blocked

    def test_no_secrets_result_backward_compatible(self):
        checks = self._passing_checks()
        # Call without secrets_result parameter at all (backward compat)
        result = calculate_risk(checks, "production")
        assert result.score == 0
        assert result.blocked is False
