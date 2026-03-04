"""Unit tests for the waiver loading, matching, and application workflow.

Covers:
  load_waivers()       — reads YAML, returns Waiver list; graceful on missing file
  _waiver_matches()    — check_id / resource_kind / resource_name / namespace / expiry
  apply_waivers()      — marks failing checks waived, builds audit trail
  Expired waivers      — not applied
  Passed checks        — never waived even when ID matches
  Partial matches      — check_id match alone is not enough when resource_kind differs
  YAML format          — various valid/invalid documents
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest
import yaml

from vlamguard.engine.waivers import _waiver_matches, apply_waivers, load_waivers
from vlamguard.models.response import PolicyCheckResult
from vlamguard.models.waiver import Waiver


# ---------------------------------------------------------------------------
# Helpers — minimal builders
# ---------------------------------------------------------------------------


def _result(
    check_id: str = "image_tag",
    *,
    passed: bool = False,
    name: str | None = None,
    severity: str = "high",
    message: str = "check failed",
) -> PolicyCheckResult:
    return PolicyCheckResult(
        check_id=check_id,
        name=name or check_id,
        passed=passed,
        severity=severity,
        message=message,
    )


def _waiver(
    check_id: str = "image_tag",
    *,
    reason: str = "Legacy image, tracked in JIRA-123",
    approved_by: str = "security-team@example.com",
    resource_kind: str | None = None,
    resource_name: str | None = None,
    namespace: str | None = None,
    expires: datetime | None = None,
) -> Waiver:
    return Waiver(
        check_id=check_id,
        reason=reason,
        approved_by=approved_by,
        resource_kind=resource_kind,
        resource_name=resource_name,
        namespace=namespace,
        expires=expires,
    )


def _future(days: int = 30) -> datetime:
    return datetime.now() + timedelta(days=days)


def _past(days: int = 1) -> datetime:
    return datetime.now() - timedelta(days=days)


def _manifest(
    kind: str = "Deployment",
    name: str = "web",
    namespace: str = "default",
) -> dict:
    return {
        "apiVersion": "apps/v1",
        "kind": kind,
        "metadata": {"name": name, "namespace": namespace},
        "spec": {},
    }


# ---------------------------------------------------------------------------
# load_waivers
# ---------------------------------------------------------------------------


class TestLoadWaivers:
    def test_load_minimal_valid_file(self, tmp_path: Path):
        waivers_file = tmp_path / "waivers.yaml"
        waivers_file.write_text(
            "waivers:\n"
            "  - check_id: image_tag\n"
            "    reason: 'Pinning tracked separately'\n"
            "    approved_by: 'ops@example.com'\n"
        )
        waivers = load_waivers(waivers_file)
        assert len(waivers) == 1
        assert waivers[0].check_id == "image_tag"
        assert waivers[0].reason == "Pinning tracked separately"
        assert waivers[0].approved_by == "ops@example.com"

    def test_load_multiple_waivers(self, tmp_path: Path):
        waivers_file = tmp_path / "waivers.yaml"
        waivers_file.write_text(
            "waivers:\n"
            "  - check_id: image_tag\n"
            "    reason: 'Reason A'\n"
            "    approved_by: 'alice@example.com'\n"
            "  - check_id: resource_limits\n"
            "    reason: 'Reason B'\n"
            "    approved_by: 'bob@example.com'\n"
        )
        waivers = load_waivers(waivers_file)
        assert len(waivers) == 2
        assert {w.check_id for w in waivers} == {"image_tag", "resource_limits"}

    def test_load_waiver_with_all_optional_fields(self, tmp_path: Path):
        expires_str = "2099-12-31T00:00:00"
        waivers_file = tmp_path / "waivers.yaml"
        waivers_file.write_text(
            f"waivers:\n"
            f"  - check_id: image_tag\n"
            f"    reason: 'Full waiver'\n"
            f"    approved_by: 'security@example.com'\n"
            f"    resource_kind: Deployment\n"
            f"    resource_name: legacy-app\n"
            f"    namespace: production\n"
            f"    expires: '{expires_str}'\n"
        )
        waivers = load_waivers(waivers_file)
        assert len(waivers) == 1
        w = waivers[0]
        assert w.resource_kind == "Deployment"
        assert w.resource_name == "legacy-app"
        assert w.namespace == "production"
        assert w.expires is not None
        assert w.expires.year == 2099

    def test_returns_empty_list_for_missing_file(self, tmp_path: Path):
        result = load_waivers(tmp_path / "does_not_exist.yaml")
        assert result == []

    def test_returns_empty_list_for_empty_file(self, tmp_path: Path):
        empty_file = tmp_path / "empty.yaml"
        empty_file.write_text("")
        result = load_waivers(empty_file)
        assert result == []

    def test_returns_empty_list_for_file_with_no_waivers_key(self, tmp_path: Path):
        f = tmp_path / "other.yaml"
        f.write_text("settings:\n  debug: true\n")
        result = load_waivers(f)
        assert result == []

    def test_returns_empty_list_for_empty_waivers_list(self, tmp_path: Path):
        f = tmp_path / "empty_list.yaml"
        f.write_text("waivers: []\n")
        result = load_waivers(f)
        assert result == []

    def test_accepts_pathlib_path(self, tmp_path: Path):
        f = tmp_path / "waivers.yaml"
        f.write_text("waivers:\n  - check_id: x\n    reason: r\n    approved_by: a\n")
        waivers = load_waivers(f)  # Path object, not str
        assert len(waivers) == 1

    def test_accepts_string_path(self, tmp_path: Path):
        f = tmp_path / "waivers.yaml"
        f.write_text("waivers:\n  - check_id: x\n    reason: r\n    approved_by: a\n")
        waivers = load_waivers(str(f))  # str, not Path
        assert len(waivers) == 1


# ---------------------------------------------------------------------------
# _waiver_matches — unit tests of the internal matcher
# ---------------------------------------------------------------------------


class TestWaiverMatches:
    def test_matches_on_check_id_alone(self):
        waiver = _waiver("image_tag")
        result = _result("image_tag", passed=False)
        assert _waiver_matches(waiver, result) is True

    def test_no_match_different_check_id(self):
        waiver = _waiver("image_tag")
        result = _result("resource_limits", passed=False)
        assert _waiver_matches(waiver, result) is False

    def test_matches_with_correct_resource_kind(self):
        waiver = _waiver("image_tag", resource_kind="Deployment")
        result = _result("image_tag", passed=False)
        manifest = _manifest(kind="Deployment")
        assert _waiver_matches(waiver, result, manifest) is True

    def test_no_match_wrong_resource_kind(self):
        waiver = _waiver("image_tag", resource_kind="StatefulSet")
        result = _result("image_tag", passed=False)
        manifest = _manifest(kind="Deployment")
        assert _waiver_matches(waiver, result, manifest) is False

    def test_matches_with_correct_resource_name(self):
        waiver = _waiver("image_tag", resource_name="legacy-app")
        result = _result("image_tag", passed=False)
        manifest = _manifest(name="legacy-app")
        assert _waiver_matches(waiver, result, manifest) is True

    def test_no_match_wrong_resource_name(self):
        waiver = _waiver("image_tag", resource_name="legacy-app")
        result = _result("image_tag", passed=False)
        manifest = _manifest(name="modern-app")
        assert _waiver_matches(waiver, result, manifest) is False

    def test_matches_with_correct_namespace(self):
        waiver = _waiver("image_tag", namespace="production")
        result = _result("image_tag", passed=False)
        manifest = _manifest(namespace="production")
        assert _waiver_matches(waiver, result, manifest) is True

    def test_no_match_wrong_namespace(self):
        waiver = _waiver("image_tag", namespace="production")
        result = _result("image_tag", passed=False)
        manifest = _manifest(namespace="staging")
        assert _waiver_matches(waiver, result, manifest) is False

    def test_matches_when_all_fields_correct(self):
        waiver = _waiver(
            "image_tag",
            resource_kind="Deployment",
            resource_name="legacy-app",
            namespace="production",
        )
        result = _result("image_tag", passed=False)
        manifest = _manifest(kind="Deployment", name="legacy-app", namespace="production")
        assert _waiver_matches(waiver, result, manifest) is True

    def test_no_match_check_id_mismatch_with_correct_resource(self):
        waiver = _waiver("image_tag", resource_kind="Deployment")
        result = _result("resource_limits", passed=False)
        manifest = _manifest(kind="Deployment")
        assert _waiver_matches(waiver, result, manifest) is False

    def test_no_manifest_uses_check_id_only(self):
        waiver = _waiver("image_tag", resource_kind="Deployment")
        result = _result("image_tag", passed=False)
        # Passing manifest=None means the kind constraint is not evaluated
        assert _waiver_matches(waiver, result, None) is True

    def test_active_waiver_without_expiry_matches(self):
        waiver = _waiver("image_tag", expires=None)
        result = _result("image_tag", passed=False)
        assert _waiver_matches(waiver, result) is True

    def test_active_waiver_with_future_expiry_matches(self):
        waiver = _waiver("image_tag", expires=_future(30))
        result = _result("image_tag", passed=False)
        assert _waiver_matches(waiver, result) is True

    def test_expired_waiver_does_not_match(self):
        waiver = _waiver("image_tag", expires=_past(1))
        result = _result("image_tag", passed=False)
        assert _waiver_matches(waiver, result) is False

    def test_expired_yesterday_does_not_match(self):
        waiver = _waiver("image_tag", expires=_past(1))
        result = _result("image_tag", passed=False)
        manifest = _manifest()
        assert _waiver_matches(waiver, result, manifest) is False


# ---------------------------------------------------------------------------
# apply_waivers — end-to-end application logic
# ---------------------------------------------------------------------------


class TestApplyWaivers:
    def test_marks_failing_check_as_waived(self):
        results = [_result("image_tag", passed=False)]
        waivers = [_waiver("image_tag")]

        updated, applied = apply_waivers(results, waivers)

        assert updated[0].waived is True
        assert updated[0].waiver_reason is not None
        assert len(applied) == 1

    def test_waived_result_retains_failed_status(self):
        """Waivers must NOT flip passed=True — the check still failed."""
        results = [_result("image_tag", passed=False)]
        waivers = [_waiver("image_tag")]

        updated, _ = apply_waivers(results, waivers)

        assert updated[0].passed is False, "Waived checks must remain failed=True"

    def test_passing_check_is_never_waived(self):
        results = [_result("image_tag", passed=True)]
        waivers = [_waiver("image_tag")]

        updated, applied = apply_waivers(results, waivers)

        assert updated[0].waived is False
        assert len(applied) == 0

    def test_no_waivers_returns_unchanged_results(self):
        results = [_result("image_tag", passed=False)]

        updated, applied = apply_waivers(results, [])

        assert updated[0].waived is False
        assert applied == []

    def test_empty_results_returns_empty(self):
        updated, applied = apply_waivers([], [_waiver("image_tag")])
        assert updated == []
        assert applied == []

    def test_expired_waiver_is_not_applied(self):
        results = [_result("image_tag", passed=False)]
        waivers = [_waiver("image_tag", expires=_past(1))]

        updated, applied = apply_waivers(results, waivers)

        assert updated[0].waived is False
        assert len(applied) == 0

    def test_future_expiry_waiver_is_applied(self):
        results = [_result("image_tag", passed=False)]
        waivers = [_waiver("image_tag", expires=_future(10))]

        updated, applied = apply_waivers(results, waivers)

        assert updated[0].waived is True
        assert len(applied) == 1

    def test_waiver_reason_carried_into_result(self):
        results = [_result("image_tag", passed=False)]
        waivers = [_waiver("image_tag", reason="Tracked in JIRA-999")]

        updated, _ = apply_waivers(results, waivers)

        assert updated[0].waiver_reason == "Tracked in JIRA-999"

    def test_audit_trail_contains_correct_fields(self):
        results = [_result("image_tag", passed=False)]
        waivers = [_waiver("image_tag", reason="Needs migration", approved_by="cto@example.com")]

        _, applied = apply_waivers(results, waivers)

        assert len(applied) == 1
        entry = applied[0]
        assert entry["check_id"] == "image_tag"
        assert entry["reason"] == "Needs migration"
        assert entry["approved_by"] == "cto@example.com"
        assert entry["expires"] is None

    def test_audit_trail_contains_expires_as_iso_string(self):
        exp = _future(15)
        results = [_result("image_tag", passed=False)]
        waivers = [_waiver("image_tag", expires=exp)]

        _, applied = apply_waivers(results, waivers)

        assert applied[0]["expires"] == exp.isoformat()

    def test_only_first_matching_waiver_is_applied(self):
        """When two waivers match the same check, only the first is applied."""
        results = [_result("image_tag", passed=False)]
        waivers = [
            _waiver("image_tag", reason="First waiver"),
            _waiver("image_tag", reason="Second waiver"),
        ]

        updated, applied = apply_waivers(results, waivers)

        assert len(applied) == 1
        assert applied[0]["reason"] == "First waiver"
        assert updated[0].waiver_reason == "First waiver"

    def test_multiple_different_checks_each_waived_independently(self):
        results = [
            _result("image_tag", passed=False),
            _result("resource_limits", passed=False),
        ]
        waivers = [
            _waiver("image_tag"),
            _waiver("resource_limits"),
        ]

        updated, applied = apply_waivers(results, waivers)

        assert updated[0].waived is True
        assert updated[1].waived is True
        assert len(applied) == 2

    def test_waiver_for_different_check_does_not_waive_another(self):
        results = [_result("image_tag", passed=False)]
        waivers = [_waiver("resource_limits")]

        updated, applied = apply_waivers(results, waivers)

        assert updated[0].waived is False
        assert len(applied) == 0

    def test_partial_match_kind_mismatch_not_waived(self):
        """check_id matches but resource_kind does not — waiver must not apply."""
        results = [_result("image_tag", passed=False)]
        waivers = [_waiver("image_tag", resource_kind="StatefulSet")]
        manifests = [_manifest(kind="Deployment")]

        updated, applied = apply_waivers(results, waivers, manifests)

        assert updated[0].waived is False
        assert len(applied) == 0

    def test_partial_match_name_mismatch_not_waived(self):
        results = [_result("image_tag", passed=False)]
        waivers = [_waiver("image_tag", resource_name="legacy-app")]
        manifests = [_manifest(name="new-app")]

        updated, applied = apply_waivers(results, waivers, manifests)

        assert updated[0].waived is False
        assert len(applied) == 0

    def test_partial_match_namespace_mismatch_not_waived(self):
        results = [_result("image_tag", passed=False)]
        waivers = [_waiver("image_tag", namespace="production")]
        manifests = [_manifest(namespace="staging")]

        updated, applied = apply_waivers(results, waivers, manifests)

        assert updated[0].waived is False

    def test_with_manifests_correct_resource_is_waived(self):
        results = [_result("image_tag", passed=False)]
        waivers = [_waiver("image_tag", resource_kind="Deployment", resource_name="legacy-app")]
        manifests = [_manifest(kind="Deployment", name="legacy-app")]

        updated, applied = apply_waivers(results, waivers, manifests)

        assert updated[0].waived is True
        assert len(applied) == 1

    def test_mixed_results_only_failing_ones_waived(self):
        results = [
            _result("image_tag", passed=True),    # passing — must not be waived
            _result("resource_limits", passed=False),
        ]
        waivers = [
            _waiver("image_tag"),
            _waiver("resource_limits"),
        ]

        updated, applied = apply_waivers(results, waivers)

        assert updated[0].waived is False, "Passed check must not be waived"
        assert updated[1].waived is True
        assert len(applied) == 1

    def test_results_list_length_unchanged(self):
        """apply_waivers must not add or remove results."""
        results = [
            _result("image_tag", passed=False),
            _result("resource_limits", passed=False),
            _result("replica_count", passed=True),
        ]
        waivers = [_waiver("image_tag")]

        updated, _ = apply_waivers(results, waivers)

        assert len(updated) == 3

    def test_unwaivable_check_preserves_all_original_fields(self):
        """Non-waived results must be left completely untouched."""
        original = _result("resource_limits", passed=False, message="limits missing")
        results = [original]
        waivers = [_waiver("image_tag")]  # Different check_id

        updated, _ = apply_waivers(results, waivers)

        r = updated[0]
        assert r.check_id == "resource_limits"
        assert r.message == "limits missing"
        assert r.waived is False
        assert r.waiver_reason is None

    def test_waived_result_preserves_original_metadata(self):
        """Waiving a result must preserve check_id, name, severity, and message."""
        original = _result("image_tag", passed=False, severity="critical", message="bad image")
        results = [original]
        waivers = [_waiver("image_tag")]

        updated, _ = apply_waivers(results, waivers)

        r = updated[0]
        assert r.check_id == "image_tag"
        assert r.severity == "critical"
        assert r.message == "bad image"


# ---------------------------------------------------------------------------
# YAML format edge cases for load_waivers
# ---------------------------------------------------------------------------


class TestWaiversYamlFormat:
    def test_waiver_with_only_required_fields(self, tmp_path: Path):
        f = tmp_path / "w.yaml"
        f.write_text(
            "waivers:\n"
            "  - check_id: replica_count\n"
            "    reason: 'Single instance for cost reasons'\n"
            "    approved_by: 'cto@example.com'\n"
        )
        waivers = load_waivers(f)
        assert len(waivers) == 1
        w = waivers[0]
        assert w.resource_kind is None
        assert w.resource_name is None
        assert w.namespace is None
        assert w.expires is None

    def test_waiver_expiry_is_parsed_as_datetime(self, tmp_path: Path):
        f = tmp_path / "w.yaml"
        f.write_text(
            "waivers:\n"
            "  - check_id: image_tag\n"
            "    reason: r\n"
            "    approved_by: a\n"
            "    expires: '2030-06-01T00:00:00'\n"
        )
        waivers = load_waivers(f)
        assert isinstance(waivers[0].expires, datetime)
        assert waivers[0].expires.year == 2030
        assert waivers[0].expires.month == 6

    def test_waiver_created_at_defaults_to_now(self, tmp_path: Path):
        f = tmp_path / "w.yaml"
        f.write_text(
            "waivers:\n"
            "  - check_id: image_tag\n"
            "    reason: r\n"
            "    approved_by: a\n"
        )
        before = datetime.now()
        waivers = load_waivers(f)
        after = datetime.now()
        assert before <= waivers[0].created_at <= after

    def test_multiple_waivers_all_loaded(self, tmp_path: Path):
        data = {
            "waivers": [
                {"check_id": f"check_{i}", "reason": f"reason {i}", "approved_by": "ops@example.com"}
                for i in range(5)
            ]
        }
        f = tmp_path / "w.yaml"
        f.write_text(yaml.dump(data))
        waivers = load_waivers(f)
        assert len(waivers) == 5
        ids = {w.check_id for w in waivers}
        assert ids == {f"check_{i}" for i in range(5)}
