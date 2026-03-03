"""Tests for the policy registry infrastructure."""

import vlamguard.engine.policies  # noqa: F401
from vlamguard.engine.registry import (
    get_all_checks,
    get_check_fns,
    get_environment_matrix,
    get_risk_points,
)


class TestPolicyRegistry:
    def test_all_checks_registered(self):
        checks = get_all_checks()
        assert len(checks) >= 5

    def test_check_ids_unique(self):
        checks = get_all_checks()
        ids = [c.check_id for c in checks]
        assert len(ids) == len(set(ids))

    def test_environment_matrix_complete(self):
        matrix = get_environment_matrix()
        checks = get_all_checks()
        for check in checks:
            assert check.check_id in matrix

    def test_risk_points_non_negative(self):
        risk_points = get_risk_points()
        for check_id, points in risk_points.items():
            assert points >= 0, f"{check_id} has negative risk_points: {points}"

    def test_categories_valid(self):
        valid = {"security", "reliability", "best-practice"}
        for check in get_all_checks():
            assert check.category in valid, f"{check.check_id} has invalid category: {check.category}"

    def test_severities_valid(self):
        valid = {"critical", "high", "medium"}
        for check in get_all_checks():
            assert check.severity in valid, f"{check.check_id} has invalid severity: {check.severity}"

    def test_get_check_fns_returns_callables(self):
        fns = get_check_fns()
        assert len(fns) >= 5
        for fn in fns:
            assert callable(fn)
