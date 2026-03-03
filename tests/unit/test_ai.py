"""Tests for AI context layer: filtering, schema validation, and client."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from vlamguard.ai.filtering import extract_metadata
from vlamguard.ai.schemas import validate_ai_response
from vlamguard.ai.context import get_ai_context
from vlamguard.models.response import PolicyCheckResult


class TestMetadataFiltering:
    def test_extracts_deployment_metadata(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web", "namespace": "production"},
            "spec": {
                "replicas": 3,
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "app", "image": "nginx:1.25.3",
                                "securityContext": {"runAsNonRoot": True, "privileged": False},
                                "resources": {
                                    "requests": {"cpu": "100m", "memory": "128Mi"},
                                    "limits": {"cpu": "500m", "memory": "256Mi"},
                                },
                            }
                        ]
                    }
                },
            },
        }
        metadata = extract_metadata(manifest)
        assert metadata["kind"] == "Deployment"
        assert metadata["name"] == "web"
        assert metadata["namespace"] == "production"
        assert metadata["replicas"] == 3
        assert len(metadata["containers"]) == 1
        assert metadata["containers"][0]["image"] == "nginx:1.25.3"

    def test_filters_out_large_fields(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web", "namespace": "default", "annotations": {"some-long-annotation": "x" * 1000}},
            "spec": {
                "replicas": 1,
                "template": {
                    "spec": {
                        "containers": [{"name": "app", "image": "nginx:1.25.3"}],
                        "volumes": [{"name": "data", "emptyDir": {}}],
                    }
                },
            },
        }
        metadata = extract_metadata(manifest)
        assert "annotations" not in metadata
        # Volumes are now included as metadata for security analysis
        assert "volumes" in metadata
        assert metadata["volumes"][0]["type"] == "emptyDir"

    def test_non_workload_minimal_metadata(self):
        manifest = {"kind": "ConfigMap", "metadata": {"name": "cfg", "namespace": "default"}, "data": {"key": "value"}}
        metadata = extract_metadata(manifest)
        assert metadata["kind"] == "ConfigMap"
        assert metadata["name"] == "cfg"


class TestSchemaValidation:
    def test_valid_response_passes(self):
        data = {
            "summary": "This deployment changes replicas.",
            "impact_analysis": [{"severity": "high", "resource": "Deployment/web", "description": "Single point of failure."}],
            "recommendations": ["Increase replicas to at least 2."],
            "rollback_suggestion": "kubectl rollout undo deployment/web",
        }
        result = validate_ai_response(data)
        assert result is not None
        assert result.summary == "This deployment changes replicas."

    def test_missing_field_returns_none(self):
        data = {"summary": "Something changed."}
        result = validate_ai_response(data)
        assert result is None

    def test_invalid_type_returns_none(self):
        result = validate_ai_response("not a dict")
        assert result is None

    def test_empty_summary_rejected_by_jsonschema(self):
        data = {
            "summary": "",
            "impact_analysis": [],
            "recommendations": ["Do something."],
            "rollback_suggestion": "kubectl rollout undo",
        }
        result = validate_ai_response(data)
        assert result is None

    def test_invalid_severity_rejected_by_jsonschema(self):
        data = {
            "summary": "Test.",
            "impact_analysis": [{"severity": "unknown", "resource": "Deployment/web", "description": "Bad."}],
            "recommendations": ["Fix it."],
            "rollback_suggestion": "kubectl rollout undo",
        }
        result = validate_ai_response(data)
        assert result is None

    def test_extra_fields_rejected_by_jsonschema(self):
        data = {
            "summary": "Test.",
            "impact_analysis": [],
            "recommendations": ["Fix it."],
            "rollback_suggestion": "kubectl rollout undo",
            "unknown_extra_field": "should fail",
        }
        result = validate_ai_response(data)
        assert result is None

    def test_empty_recommendations_rejected_by_jsonschema(self):
        data = {
            "summary": "Test.",
            "impact_analysis": [],
            "recommendations": [],
            "rollback_suggestion": "kubectl rollout undo",
        }
        result = validate_ai_response(data)
        assert result is None


class TestGetAIContext:
    @pytest.mark.asyncio
    async def test_successful_call(self):
        ai_response = {
            "choices": [{
                "message": {
                    "content": json.dumps({
                        "summary": "Test summary.",
                        "impact_analysis": [{"severity": "medium", "resource": "Deployment/web", "description": "Test impact."}],
                        "recommendations": ["Do something."],
                        "rollback_suggestion": "kubectl rollout undo",
                    })
                }
            }]
        }

        # httpx.Response methods (json, raise_for_status) are synchronous — use MagicMock
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = ai_response
        mock_response.raise_for_status = MagicMock()

        with patch("vlamguard.ai.context.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value = mock_client

            result = await get_ai_context(
                manifests_metadata=[{"kind": "Deployment", "name": "web"}],
                policy_results=[], environment="production",
            )

        assert result is not None
        assert result.summary == "Test summary."

    @pytest.mark.asyncio
    async def test_timeout_returns_none(self):
        with patch("vlamguard.ai.context.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.post.side_effect = httpx.TimeoutException("timeout")
            mock_client_cls.return_value = mock_client

            result = await get_ai_context(manifests_metadata=[], policy_results=[], environment="production")

        assert result is None

    @pytest.mark.asyncio
    async def test_invalid_json_returns_none(self):
        # httpx.Response methods (json, raise_for_status) are synchronous — use MagicMock
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"choices": [{"message": {"content": "not json"}}]}
        mock_response.raise_for_status = MagicMock()

        with patch("vlamguard.ai.context.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value = mock_client

            result = await get_ai_context(manifests_metadata=[], policy_results=[], environment="production")

        assert result is None
