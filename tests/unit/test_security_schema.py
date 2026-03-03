"""Tests for AI security schema validation."""

from vlamguard.ai.schemas import validate_ai_response, validate_security_ai_response


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
