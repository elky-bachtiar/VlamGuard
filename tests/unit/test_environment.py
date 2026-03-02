"""Tests for binary environment logic."""

from vlamguard.engine.environment import CheckBehavior, get_check_behavior


class TestEnvironmentLogic:
    """Environment matrix: production=strict, everything else=soft."""

    def test_production_image_tag_is_hard_block(self):
        assert get_check_behavior("image_tag", "production") == CheckBehavior.HARD_BLOCK

    def test_production_security_context_is_hard_block(self):
        assert get_check_behavior("security_context", "production") == CheckBehavior.HARD_BLOCK

    def test_production_rbac_scope_is_hard_block(self):
        assert get_check_behavior("rbac_scope", "production") == CheckBehavior.HARD_BLOCK

    def test_production_resource_limits_is_soft_risk(self):
        assert get_check_behavior("resource_limits", "production") == CheckBehavior.SOFT_RISK

    def test_production_replica_count_is_soft_risk(self):
        assert get_check_behavior("replica_count", "production") == CheckBehavior.SOFT_RISK

    def test_dev_image_tag_is_soft_risk(self):
        assert get_check_behavior("image_tag", "dev") == CheckBehavior.SOFT_RISK

    def test_dev_security_context_is_soft_risk(self):
        assert get_check_behavior("security_context", "dev") == CheckBehavior.SOFT_RISK

    def test_dev_rbac_scope_is_hard_block(self):
        assert get_check_behavior("rbac_scope", "dev") == CheckBehavior.HARD_BLOCK

    def test_dev_resource_limits_is_off(self):
        assert get_check_behavior("resource_limits", "dev") == CheckBehavior.OFF

    def test_dev_replica_count_is_off(self):
        assert get_check_behavior("replica_count", "dev") == CheckBehavior.OFF

    def test_staging_same_as_dev(self):
        assert get_check_behavior("image_tag", "staging") == CheckBehavior.SOFT_RISK
        assert get_check_behavior("rbac_scope", "staging") == CheckBehavior.HARD_BLOCK
        assert get_check_behavior("resource_limits", "staging") == CheckBehavior.OFF

    def test_unknown_env_treated_as_non_production(self):
        assert get_check_behavior("image_tag", "test") == CheckBehavior.SOFT_RISK
