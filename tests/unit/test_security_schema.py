"""Tests for AI security schema validation."""

from unittest.mock import patch

from vlamguard.ai.schemas import validate_ai_response, validate_security_ai_response
from vlamguard.models.response import Recommendation


class TestSecuritySchemaValidation:
    def test_valid_response_with_secrets_detection(self):
        data = {
            "summary": "Security scan found issues.",
            "impact_analysis": [{"severity": "critical", "resource": "Deployment/web", "description": "Secret found."}],
            "recommendations": ["Move secrets to K8s Secrets."],
            "rollback_suggestion": "kubectl rollout undo",
            "secrets_detection": {
                "summary": "1 confirmed secret in production.",
                "findings": [
                    {
                        "location": "Deployment/backend → env/DATABASE_URL",
                        "ai_context": "Hardcoded DB credential",
                        "recommendation": "Use Kubernetes Secrets",
                        "effort": "low",
                    }
                ],
            },
        }
        result = validate_ai_response(data)
        assert result is not None

        sec = validate_security_ai_response(data)
        assert sec is not None
        assert "secrets_detection" in sec
        assert sec["secrets_detection"]["summary"] == "1 confirmed secret in production."

    def test_valid_response_with_hardening_recs(self):
        data = {
            "summary": "Security scan complete.",
            "impact_analysis": [],
            "recommendations": ["Enable seccomp."],
            "rollback_suggestion": "kubectl rollout undo",
            "hardening_recommendations": [
                {
                    "priority": 1,
                    "category": "container",
                    "action": "Enable read-only root filesystem",
                    "effort": "low",
                    "impact": "high",
                    "details": "Prevents runtime modifications",
                },
                {
                    "priority": 2,
                    "category": "network",
                    "action": "Add NetworkPolicy",
                    "effort": "medium",
                    "impact": "high",
                },
            ],
        }
        result = validate_ai_response(data)
        assert result is not None

        sec = validate_security_ai_response(data)
        assert sec is not None
        recs = sec["hardening_recommendations"]
        assert len(recs) == 2
        assert recs[0].priority == 1
        assert recs[0].category == "container"
        assert recs[1].effort == "medium"

    def test_response_without_security_fields(self):
        data = {
            "summary": "Normal response.",
            "impact_analysis": [],
            "recommendations": ["Do something."],
            "rollback_suggestion": "kubectl rollout undo",
        }
        sec = validate_security_ai_response(data)
        assert sec is None

    def test_invalid_hardening_category_rejected(self):
        data = {
            "summary": "Test.",
            "impact_analysis": [],
            "recommendations": ["Do something."],
            "rollback_suggestion": "kubectl rollout undo",
            "hardening_recommendations": [
                {
                    "priority": 1,
                    "category": "invalid_category",
                    "action": "Test",
                    "effort": "low",
                    "impact": "high",
                },
            ],
        }
        result = validate_ai_response(data)
        assert result is None

    def test_non_dict_returns_none(self):
        assert validate_security_ai_response("not a dict") is None
        assert validate_security_ai_response(42) is None
        assert validate_security_ai_response(None) is None

    # --- Lines 107-108: Pydantic construction error after JSON Schema passes ---

    def test_validate_ai_response_returns_none_when_pydantic_construction_fails(self):
        """JSON Schema passes (mocked), but ImpactItem(**item) raises TypeError when item
        is not a dict. This exercises the except branch at lines 107-108."""
        data = {
            "summary": "Valid summary.",
            "impact_analysis": ["not-a-dict"],  # passes schema when schema is mocked, breaks **item
            "recommendations": ["Do something."],
            "rollback_suggestion": "kubectl rollout undo",
        }
        with patch("vlamguard.ai.schemas.jsonschema.validate"):
            result = validate_ai_response(data)
        assert result is None

    def test_validate_ai_response_returns_none_when_impact_item_missing_field(self):
        """JSON Schema passes (mocked), but ImpactItem construction fails because a
        required field is missing. Exercises the except branch at lines 107-108."""
        data = {
            "summary": "Valid summary.",
            # impact_analysis item missing 'resource' and 'description' — Pydantic raises ValidationError
            "impact_analysis": [{"severity": "high"}],
            "recommendations": ["Do something."],
            "rollback_suggestion": "kubectl rollout undo",
        }
        with patch("vlamguard.ai.schemas.jsonschema.validate"):
            result = validate_ai_response(data)
        assert result is None

    # --- Lines 140-141: HardeningAction construction error → continue ---

    def test_validate_security_ai_response_skips_malformed_hardening_items(self):
        """A hardening item that is not a dict causes KeyError on item["priority"],
        hitting the except/continue at lines 140-141. Valid items are still returned."""
        data = {
            "hardening_recommendations": [
                {
                    "priority": 1,
                    "category": "container",
                    "action": "Set readOnlyRootFilesystem",
                    "effort": "low",
                    "impact": "high",
                },
                "not-a-dict",  # triggers KeyError in item["priority"] → continue
                {
                    "priority": 3,
                    "category": "network",
                    "action": "Add NetworkPolicy",
                    "effort": "medium",
                    "impact": "high",
                },
            ]
        }
        result = validate_security_ai_response(data)
        assert result is not None
        recs = result["hardening_recommendations"]
        # Only the two valid items survive; the malformed one was skipped
        assert len(recs) == 2
        assert recs[0].priority == 1
        assert recs[1].priority == 3

    def test_validate_security_ai_response_skips_item_missing_required_fields(self):
        """A hardening item missing required fields causes KeyError, hitting the
        except/continue branch at lines 140-141."""
        data = {
            "hardening_recommendations": [
                # Missing 'effort' and 'impact' — KeyError on item["effort"]
                {
                    "priority": 1,
                    "category": "container",
                    "action": "Set runAsNonRoot",
                },
                {
                    "priority": 2,
                    "category": "operational",
                    "action": "Add liveness probe",
                    "effort": "low",
                    "impact": "medium",
                },
            ]
        }
        result = validate_security_ai_response(data)
        assert result is not None
        recs = result["hardening_recommendations"]
        assert len(recs) == 1
        assert recs[0].priority == 2

    def test_validate_security_ai_response_all_hardening_items_malformed_returns_empty_list(self):
        """When every hardening item is malformed the list is empty, but the key is still
        present and the result dict is non-None (because hardening_recommendations key exists)."""
        data = {
            "hardening_recommendations": [
                "bad-item-1",
                "bad-item-2",
            ]
        }
        result = validate_security_ai_response(data)
        # result dict still has the key (with empty list) so it is not None
        assert result is not None
        assert result["hardening_recommendations"] == []

    def test_recommendations_accepts_mixed_array(self):
        """Schema must accept an array with both plain strings and recommendation objects."""
        data = {
            "summary": "Mixed recommendations.",
            "impact_analysis": [],
            "recommendations": [
                "Pin image tag.",
                {
                    "action": "Set resource limits",
                    "reason": "Without limits a pod can starve other workloads.",
                    "resource": "Deployment/web",
                    "yaml_snippet": "limits:\n  cpu: 500m",
                },
            ],
            "rollback_suggestion": "kubectl rollout undo",
        }
        result = validate_ai_response(data)
        assert result is not None
        assert isinstance(result.recommendations[0], str)
        assert isinstance(result.recommendations[1], Recommendation)
        assert result.recommendations[1].resource == "Deployment/web"
        assert result.recommendations[1].reason == "Without limits a pod can starve other workloads."

    def test_recommendations_object_without_optional_fields(self):
        """A recommendation object with only 'action' must be accepted."""
        data = {
            "summary": "Action only.",
            "impact_analysis": [],
            "recommendations": [{"action": "Enable probes"}],
            "rollback_suggestion": "kubectl rollout undo",
        }
        result = validate_ai_response(data)
        assert result is not None
        rec = result.recommendations[0]
        assert isinstance(rec, Recommendation)
        assert rec.reason is None
        assert rec.resource is None
        assert rec.yaml_snippet is None

    def test_recommendations_object_with_extra_field_rejected(self):
        """A recommendation object with unknown fields must be rejected (additionalProperties: false)."""
        data = {
            "summary": "Bad rec.",
            "impact_analysis": [],
            "recommendations": [{"action": "Do something", "unknown_field": "bad"}],
            "rollback_suggestion": "kubectl rollout undo",
        }
        result = validate_ai_response(data)
        assert result is None

    def test_hardening_with_resource_field(self):
        """Hardening recommendations must accept the resource field."""
        data = {
            "summary": "Hardening test.",
            "impact_analysis": [],
            "recommendations": ["Fix it."],
            "rollback_suggestion": "kubectl rollout undo",
            "hardening_recommendations": [
                {
                    "priority": 1,
                    "category": "container",
                    "action": "Set readOnlyRootFilesystem",
                    "effort": "low",
                    "impact": "high",
                    "resource": "Deployment/web",
                    "yaml_hint": "readOnlyRootFilesystem: true",
                },
            ],
        }
        result = validate_ai_response(data)
        assert result is not None

        sec = validate_security_ai_response(data)
        assert sec is not None
        recs = sec["hardening_recommendations"]
        assert len(recs) == 1
        assert recs[0].resource == "Deployment/web"
