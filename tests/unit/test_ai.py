"""Tests for AI context layer: filtering, schema validation, and client."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from vlamguard.ai.filtering import extract_metadata
from vlamguard.ai.schemas import validate_ai_response
from vlamguard.ai.context import _get_timeout, get_ai_context, get_security_ai_context
from vlamguard.models.response import (
    PolicyCheckResult,
    Recommendation,
    SecretFinding,
    SecretsDetectionResult,
)


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

    # --- Lines 17-25: Service metadata extraction ---

    def test_service_extracts_type_and_ports(self):
        manifest = {
            "kind": "Service",
            "metadata": {"name": "web-svc", "namespace": "production"},
            "spec": {
                "type": "LoadBalancer",
                "ports": [
                    {"port": 80, "targetPort": 8080, "protocol": "TCP"},
                    {"port": 443, "targetPort": 8443, "protocol": "TCP"},
                ],
            },
        }
        metadata = extract_metadata(manifest)
        assert metadata["kind"] == "Service"
        assert metadata["name"] == "web-svc"
        assert metadata["service_type"] == "LoadBalancer"
        assert len(metadata["ports"]) == 2
        assert metadata["ports"][0]["port"] == 80
        assert metadata["ports"][0]["targetPort"] == 8080
        assert metadata["ports"][0]["protocol"] == "TCP"
        assert metadata["ports"][1]["port"] == 443
        # Service returns early — no workload-only fields
        assert "replicas" not in metadata
        assert "containers" not in metadata

    def test_service_defaults_to_clusterip_when_type_absent(self):
        manifest = {
            "kind": "Service",
            "metadata": {"name": "internal-svc", "namespace": "default"},
            "spec": {},
        }
        metadata = extract_metadata(manifest)
        assert metadata["service_type"] == "ClusterIP"
        assert "ports" not in metadata

    def test_service_with_empty_ports_omits_ports_key(self):
        manifest = {
            "kind": "Service",
            "metadata": {"name": "headless", "namespace": "default"},
            "spec": {"type": "ClusterIP", "ports": []},
        }
        metadata = extract_metadata(manifest)
        assert metadata["service_type"] == "ClusterIP"
        assert "ports" not in metadata

    def test_service_port_defaults_protocol_to_tcp(self):
        manifest = {
            "kind": "Service",
            "metadata": {"name": "api-svc", "namespace": "default"},
            "spec": {
                "type": "ClusterIP",
                "ports": [{"port": 8080, "targetPort": 8080}],
            },
        }
        metadata = extract_metadata(manifest)
        assert metadata["ports"][0]["protocol"] == "TCP"

    # --- Line 40: hostNetwork / hostPID / hostIPC True flags ---

    def test_host_namespace_flags_included_when_true(self):
        manifest = {
            "kind": "DaemonSet",
            "metadata": {"name": "node-agent", "namespace": "kube-system"},
            "spec": {
                "replicas": 1,
                "template": {
                    "spec": {
                        "hostNetwork": True,
                        "hostPID": True,
                        "hostIPC": True,
                        "containers": [{"name": "agent", "image": "agent:1.0"}],
                    }
                },
            },
        }
        metadata = extract_metadata(manifest)
        assert metadata["hostNetwork"] is True
        assert metadata["hostPID"] is True
        assert metadata["hostIPC"] is True

    def test_host_namespace_flags_absent_when_false(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "app", "namespace": "default"},
            "spec": {
                "replicas": 1,
                "template": {
                    "spec": {
                        "hostNetwork": False,
                        "hostPID": False,
                        "containers": [{"name": "app", "image": "app:1.0"}],
                    }
                },
            },
        }
        metadata = extract_metadata(manifest)
        assert "hostNetwork" not in metadata
        assert "hostPID" not in metadata
        assert "hostIPC" not in metadata

    def test_host_namespace_flags_absent_when_not_set(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "app", "namespace": "default"},
            "spec": {
                "replicas": 1,
                "template": {"spec": {"containers": [{"name": "app", "image": "app:1.0"}]}},
            },
        }
        metadata = extract_metadata(manifest)
        assert "hostNetwork" not in metadata
        assert "hostPID" not in metadata
        assert "hostIPC" not in metadata

    # --- Line 49: hostPath volume type ---

    def test_hostpath_volume_type_extracted(self):
        manifest = {
            "kind": "DaemonSet",
            "metadata": {"name": "logger", "namespace": "kube-system"},
            "spec": {
                "replicas": 1,
                "template": {
                    "spec": {
                        "containers": [{"name": "logger", "image": "logger:1.0"}],
                        "volumes": [{"name": "host-logs", "hostPath": {"path": "/var/log"}}],
                    }
                },
            },
        }
        metadata = extract_metadata(manifest)
        assert len(metadata["volumes"]) == 1
        assert metadata["volumes"][0]["name"] == "host-logs"
        assert metadata["volumes"][0]["type"] == "hostPath"

    # --- Lines 52-57: configMap, secret, PVC volume types ---

    def test_configmap_volume_type_extracted(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "app", "namespace": "default"},
            "spec": {
                "replicas": 1,
                "template": {
                    "spec": {
                        "containers": [{"name": "app", "image": "app:1.0"}],
                        "volumes": [{"name": "config-vol", "configMap": {"name": "app-config"}}],
                    }
                },
            },
        }
        metadata = extract_metadata(manifest)
        assert metadata["volumes"][0]["type"] == "configMap"

    def test_secret_volume_type_extracted(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "app", "namespace": "default"},
            "spec": {
                "replicas": 1,
                "template": {
                    "spec": {
                        "containers": [{"name": "app", "image": "app:1.0"}],
                        "volumes": [{"name": "creds", "secret": {"secretName": "app-secret"}}],
                    }
                },
            },
        }
        metadata = extract_metadata(manifest)
        assert metadata["volumes"][0]["type"] == "secret"

    def test_pvc_volume_type_extracted(self):
        manifest = {
            "kind": "StatefulSet",
            "metadata": {"name": "db", "namespace": "production"},
            "spec": {
                "replicas": 1,
                "template": {
                    "spec": {
                        "containers": [{"name": "db", "image": "postgres:15"}],
                        "volumes": [
                            {
                                "name": "data",
                                "persistentVolumeClaim": {"claimName": "db-pvc"},
                            }
                        ],
                    }
                },
            },
        }
        metadata = extract_metadata(manifest)
        assert metadata["volumes"][0]["type"] == "pvc"

    def test_multiple_volume_types_in_single_manifest(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "app", "namespace": "default"},
            "spec": {
                "replicas": 1,
                "template": {
                    "spec": {
                        "containers": [{"name": "app", "image": "app:1.0"}],
                        "volumes": [
                            {"name": "host-sock", "hostPath": {"path": "/var/run/docker.sock"}},
                            {"name": "config", "configMap": {"name": "cfg"}},
                            {"name": "tls", "secret": {"secretName": "tls-cert"}},
                            {"name": "data", "persistentVolumeClaim": {"claimName": "data-pvc"}},
                            {"name": "tmp", "emptyDir": {}},
                        ],
                    }
                },
            },
        }
        metadata = extract_metadata(manifest)
        vol_types = {v["name"]: v.get("type") for v in metadata["volumes"]}
        assert vol_types["host-sock"] == "hostPath"
        assert vol_types["config"] == "configMap"
        assert vol_types["tls"] == "secret"
        assert vol_types["data"] == "pvc"
        assert vol_types["tmp"] == "emptyDir"

    # --- Line 73: capabilities extraction from securityContext ---

    def test_capabilities_extracted_from_security_context(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "privileged-app", "namespace": "default"},
            "spec": {
                "replicas": 1,
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "app",
                                "image": "app:1.0",
                                "securityContext": {
                                    "capabilities": {
                                        "add": ["SYS_ADMIN", "NET_ADMIN"],
                                        "drop": ["ALL"],
                                    }
                                },
                            }
                        ]
                    }
                },
            },
        }
        metadata = extract_metadata(manifest)
        container = metadata["containers"][0]
        assert "securityContext" in container
        assert "capabilities" in container
        assert container["capabilities"]["add"] == ["SYS_ADMIN", "NET_ADMIN"]
        assert container["capabilities"]["drop"] == ["ALL"]

    def test_empty_capabilities_dict_not_extracted(self):
        """When securityContext has no capabilities key, the capabilities key is not in container metadata."""
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "app", "namespace": "default"},
            "spec": {
                "replicas": 1,
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "app",
                                "image": "app:1.0",
                                "securityContext": {"runAsNonRoot": True},
                            }
                        ]
                    }
                },
            },
        }
        metadata = extract_metadata(manifest)
        container = metadata["containers"][0]
        assert "securityContext" in container
        # capabilities key is absent from securityContext → get returns {} → falsy → not added
        assert "capabilities" not in container

    def test_init_containers_capabilities_extracted(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "app", "namespace": "default"},
            "spec": {
                "replicas": 1,
                "template": {
                    "spec": {
                        "containers": [{"name": "main", "image": "main:1.0"}],
                        "initContainers": [
                            {
                                "name": "init",
                                "image": "busybox:1.35",
                                "securityContext": {
                                    "capabilities": {"add": ["NET_BIND_SERVICE"]}
                                },
                            }
                        ],
                    }
                },
            },
        }
        metadata = extract_metadata(manifest)
        all_containers = metadata["containers"]
        assert len(all_containers) == 2
        init = next(c for c in all_containers if c["name"] == "init")
        assert init["capabilities"] == {"add": ["NET_BIND_SERVICE"]}


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

    def test_structured_recommendation_object_passes(self):
        data = {
            "summary": "Deployment needs hardening.",
            "impact_analysis": [],
            "recommendations": [
                {
                    "action": "Set runAsNonRoot: true",
                    "reason": "Running as root allows container escape attacks.",
                    "resource": "Deployment/web",
                    "yaml_snippet": "runAsNonRoot: true",
                },
            ],
            "rollback_suggestion": "kubectl rollout undo",
        }
        result = validate_ai_response(data)
        assert result is not None
        rec = result.recommendations[0]
        assert isinstance(rec, Recommendation)
        assert rec.action == "Set runAsNonRoot: true"
        assert rec.reason == "Running as root allows container escape attacks."
        assert rec.resource == "Deployment/web"
        assert rec.yaml_snippet == "runAsNonRoot: true"

    def test_mixed_recommendations_string_and_object(self):
        data = {
            "summary": "Mixed recommendations.",
            "impact_analysis": [],
            "recommendations": [
                "Pin image tag to specific version.",
                {"action": "Set resource limits", "resource": "Deployment/api"},
            ],
            "rollback_suggestion": "kubectl rollout undo",
        }
        result = validate_ai_response(data)
        assert result is not None
        assert isinstance(result.recommendations[0], str)
        assert isinstance(result.recommendations[1], Recommendation)
        assert result.recommendations[1].resource == "Deployment/api"
        assert result.recommendations[1].yaml_snippet is None

    def test_recommendation_object_action_only(self):
        data = {
            "summary": "Minimal object.",
            "impact_analysis": [],
            "recommendations": [{"action": "Enable readiness probe"}],
            "rollback_suggestion": "kubectl rollout undo",
        }
        result = validate_ai_response(data)
        assert result is not None
        rec = result.recommendations[0]
        assert isinstance(rec, Recommendation)
        assert rec.resource is None
        assert rec.yaml_snippet is None


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


# ---------------------------------------------------------------------------
# Helpers shared by new test classes
# ---------------------------------------------------------------------------

def _make_policy_result(
    check_id: str = "replicas",
    name: str = "Replica Count",
    passed: bool = True,
    severity: str = "medium",
    message: str = "OK",
) -> PolicyCheckResult:
    return PolicyCheckResult(
        check_id=check_id,
        name=name,
        passed=passed,
        severity=severity,
        message=message,
    )


def _make_ai_response_payload(extra: dict | None = None) -> dict:
    """Return a minimal valid AI JSON response dict, optionally merged with *extra*."""
    payload: dict = {
        "summary": "Security summary.",
        "impact_analysis": [
            {"severity": "high", "resource": "Deployment/web", "description": "Pod security risk."}
        ],
        "recommendations": ["Remove privileged containers."],
        "rollback_suggestion": "kubectl rollout undo deployment/web",
    }
    if extra:
        payload.update(extra)
    return payload


def _mock_async_client_for_payload(response_payload: dict) -> AsyncMock:
    """Return a configured AsyncMock for httpx.AsyncClient whose post() returns *response_payload*."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {
        "choices": [{"message": {"content": json.dumps(response_payload)}}]
    }

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post.return_value = mock_response
    return mock_client


# ---------------------------------------------------------------------------
# Tests for _get_timeout()
# ---------------------------------------------------------------------------


class TestGetTimeout:
    def test_returns_default_when_env_not_set(self, monkeypatch):
        monkeypatch.delenv("VLAM_AI_TIMEOUT", raising=False)
        result = _get_timeout()
        assert result == 120

    def test_returns_env_value_when_valid_integer(self, monkeypatch):
        monkeypatch.setenv("VLAM_AI_TIMEOUT", "60")
        result = _get_timeout()
        assert result == 60

    def test_returns_default_when_env_value_is_non_numeric_string(self, monkeypatch):
        monkeypatch.setenv("VLAM_AI_TIMEOUT", "not-a-number")
        result = _get_timeout()
        assert result == 120

    def test_returns_default_when_env_value_is_float_string(self, monkeypatch):
        # int("3.5") raises ValueError — must fall back to default
        monkeypatch.setenv("VLAM_AI_TIMEOUT", "3.5")
        result = _get_timeout()
        assert result == 120


# ---------------------------------------------------------------------------
# Tests for get_ai_context() with security_findings
# ---------------------------------------------------------------------------


class TestGetAIContextWithSecurityFindings:
    @pytest.mark.asyncio
    async def test_secrets_detection_block_appears_in_sent_payload(self):
        """When security_findings contains secrets_detection, user_data must include
        a security_scan.secrets block in the JSON forwarded to the AI."""
        captured_calls: list[dict] = []

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "choices": [{"message": {"content": json.dumps(_make_ai_response_payload())}}]
        }

        async def capture_post(url, *, headers, json):  # noqa: A002
            captured_calls.append(json)
            return mock_response

        with patch("vlamguard.ai.context.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.post.side_effect = capture_post
            mock_client_cls.return_value = mock_client

            security_findings = {
                "secrets_detection": {
                    "total_suspects": 2,
                    "confirmed_secrets": 1,
                    "hard_blocks": [
                        {"type": "aws_access_key", "location": "env/AWS_KEY", "detection": "deterministic"}
                    ],
                    "soft_risks": [
                        {"type": "high_entropy_string", "location": "env/TOKEN", "detection": "entropy"}
                    ],
                }
            }

            result = await get_ai_context(
                manifests_metadata=[{"kind": "Deployment", "name": "web"}],
                policy_results=[],
                environment="production",
                security_findings=security_findings,
            )

        assert result is not None
        assert result.summary == "Security summary."

        # Verify the payload sent to the AI contained the security_scan block
        assert len(captured_calls) == 1
        sent_user_content = json.loads(captured_calls[0]["messages"][1]["content"])
        assert "security_scan" in sent_user_content
        secrets_block = sent_user_content["security_scan"]["secrets"]
        assert secrets_block["total_suspects"] == 2
        assert secrets_block["confirmed_secrets"] == 1
        # 1 hard_block + 1 soft_risk = 2 findings total
        assert len(secrets_block["findings"]) == 2

    @pytest.mark.asyncio
    async def test_extended_checks_block_appears_in_sent_payload(self):
        """When security_findings contains extended_checks, user_data must include
        a security_scan.extended_checks list in the JSON forwarded to the AI."""
        captured_calls: list[dict] = []

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "choices": [{"message": {"content": json.dumps(_make_ai_response_payload())}}]
        }

        async def capture_post(url, *, headers, json):  # noqa: A002
            captured_calls.append(json)
            return mock_response

        with patch("vlamguard.ai.context.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.post.side_effect = capture_post
            mock_client_cls.return_value = mock_client

            extended = _make_policy_result(
                check_id="host_namespace", name="Host Namespace", passed=False, message="hostPID used"
            )
            security_findings = {"extended_checks": [extended]}

            result = await get_ai_context(
                manifests_metadata=[],
                policy_results=[],
                environment="staging",
                security_findings=security_findings,
            )

        assert result is not None
        sent_user_content = json.loads(captured_calls[0]["messages"][1]["content"])
        assert "security_scan" in sent_user_content
        ext_checks = sent_user_content["security_scan"]["extended_checks"]
        assert len(ext_checks) == 1
        assert ext_checks[0]["check_id"] == "host_namespace"
        assert ext_checks[0]["passed"] is False

    @pytest.mark.asyncio
    async def test_security_findings_selects_security_system_prompt(self):
        """When security_findings is provided, the security system prompt (not standard) is sent."""
        captured_messages: list[list] = []

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "choices": [{"message": {"content": json.dumps(_make_ai_response_payload())}}]
        }

        async def capture_post(url, *, headers, json):  # noqa: A002
            captured_messages.append(json["messages"])
            return mock_response

        with patch("vlamguard.ai.context.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.post.side_effect = capture_post
            mock_client_cls.return_value = mock_client

            await get_ai_context(
                manifests_metadata=[],
                policy_results=[],
                environment="production",
                security_findings={
                    "secrets_detection": {
                        "total_suspects": 0,
                        "confirmed_secrets": 0,
                        "hard_blocks": [],
                        "soft_risks": [],
                    }
                },
            )

        system_content = captured_messages[0][0]["content"]
        assert "security analyst" in system_content
        assert "hardening_recommendations" in system_content

    @pytest.mark.asyncio
    async def test_none_security_findings_selects_standard_system_prompt(self):
        """When security_findings is None, the standard risk analyst prompt is used."""
        captured_messages: list[list] = []

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "choices": [{"message": {"content": json.dumps(_make_ai_response_payload())}}]
        }

        async def capture_post(url, *, headers, json):  # noqa: A002
            captured_messages.append(json["messages"])
            return mock_response

        with patch("vlamguard.ai.context.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.post.side_effect = capture_post
            mock_client_cls.return_value = mock_client

            await get_ai_context(
                manifests_metadata=[],
                policy_results=[],
                environment="production",
                security_findings=None,
            )

        system_content = captured_messages[0][0]["content"]
        assert "risk analyst" in system_content
        # Standard prompt must NOT mention hardening_recommendations
        assert "hardening_recommendations" not in system_content


# ---------------------------------------------------------------------------
# Tests for get_security_ai_context()
# ---------------------------------------------------------------------------


class TestGetSecurityAIContext:
    @pytest.mark.asyncio
    async def test_successful_call_without_secrets_result(self):
        """Returns (AIContext, [], None) when AI responds with no security extras."""
        payload = _make_ai_response_payload()

        with patch("vlamguard.ai.context.httpx.AsyncClient") as mock_client_cls:
            mock_client_cls.return_value = _mock_async_client_for_payload(payload)

            ai_context, hardening_recs, secrets_ai_data = await get_security_ai_context(
                manifests_metadata=[{"kind": "Deployment", "name": "web"}],
                policy_results=[],
                secrets_result=None,
                environment="production",
            )

        assert ai_context is not None
        assert ai_context.summary == "Security summary."
        assert hardening_recs == []
        assert secrets_ai_data is None

    @pytest.mark.asyncio
    async def test_successful_call_with_secrets_result(self):
        """When secrets_result is provided, function still returns a valid AIContext."""
        secret_finding = SecretFinding(
            severity="critical",
            type="aws_access_key",
            location="env/AWS_ACCESS_KEY",
            pattern="aws_access_key",
            detection="deterministic",
        )
        secrets_result = SecretsDetectionResult(
            total_suspects=1,
            confirmed_secrets=1,
            false_positives=0,
            hard_blocks=[secret_finding],
            soft_risks=[],
        )

        payload = _make_ai_response_payload()

        with patch("vlamguard.ai.context.httpx.AsyncClient") as mock_client_cls:
            mock_client_cls.return_value = _mock_async_client_for_payload(payload)

            ai_context, hardening_recs, secrets_ai_data = await get_security_ai_context(
                manifests_metadata=[],
                policy_results=[],
                secrets_result=secrets_result,
                environment="production",
            )

        assert ai_context is not None
        assert hardening_recs == []
        assert secrets_ai_data is None

    @pytest.mark.asyncio
    async def test_returns_hardening_recs_when_ai_provides_them(self):
        """Hardening recommendations in AI response are parsed into HardeningAction objects."""
        payload = _make_ai_response_payload(
            extra={
                "hardening_recommendations": [
                    {
                        "priority": 1,
                        "category": "container",
                        "action": "Set runAsNonRoot: true",
                        "effort": "low",
                        "impact": "high",
                        "details": "Prevent root container execution.",
                        "yaml_hint": "securityContext:\n  runAsNonRoot: true",
                    },
                    {
                        "priority": 2,
                        "category": "network",
                        "action": "Use ClusterIP instead of LoadBalancer",
                        "effort": "medium",
                        "impact": "medium",
                    },
                ]
            }
        )

        with patch("vlamguard.ai.context.httpx.AsyncClient") as mock_client_cls:
            mock_client_cls.return_value = _mock_async_client_for_payload(payload)

            ai_context, hardening_recs, secrets_ai_data = await get_security_ai_context(
                manifests_metadata=[],
                policy_results=[],
                secrets_result=None,
                environment="staging",
            )

        assert ai_context is not None
        assert len(hardening_recs) == 2
        assert hardening_recs[0].priority == 1
        assert hardening_recs[0].category == "container"
        assert hardening_recs[0].action == "Set runAsNonRoot: true"
        assert hardening_recs[0].effort == "low"
        assert hardening_recs[0].impact == "high"
        assert hardening_recs[0].yaml_hint == "securityContext:\n  runAsNonRoot: true"
        assert hardening_recs[1].priority == 2
        assert hardening_recs[1].category == "network"
        assert secrets_ai_data is None

    @pytest.mark.asyncio
    async def test_returns_secrets_ai_data_when_ai_provides_it(self):
        """secrets_detection in AI response is returned as secrets_ai_data dict."""
        payload = _make_ai_response_payload(
            extra={
                "secrets_detection": {
                    "summary": "One AWS key detected in environment variables.",
                    "findings": [
                        {
                            "location": "env/AWS_ACCESS_KEY",
                            "ai_context": "Hardcoded AWS key exposes cloud resources.",
                            "recommendation": "Use IRSA or Secrets Manager instead.",
                            "effort": "medium",
                        }
                    ],
                }
            }
        )

        with patch("vlamguard.ai.context.httpx.AsyncClient") as mock_client_cls:
            mock_client_cls.return_value = _mock_async_client_for_payload(payload)

            ai_context, hardening_recs, secrets_ai_data = await get_security_ai_context(
                manifests_metadata=[],
                policy_results=[],
                secrets_result=None,
                environment="production",
            )

        assert ai_context is not None
        assert secrets_ai_data is not None
        assert secrets_ai_data["summary"] == "One AWS key detected in environment variables."
        assert len(secrets_ai_data["findings"]) == 1
        assert secrets_ai_data["findings"][0]["location"] == "env/AWS_ACCESS_KEY"
        assert hardening_recs == []

    @pytest.mark.asyncio
    async def test_returns_both_hardening_and_secrets_ai_data(self):
        """Both hardening_recommendations and secrets_detection are extracted together."""
        payload = _make_ai_response_payload(
            extra={
                "hardening_recommendations": [
                    {
                        "priority": 1,
                        "category": "supply_chain",
                        "action": "Pin image digests",
                        "effort": "low",
                        "impact": "high",
                    }
                ],
                "secrets_detection": {
                    "summary": "Database password found.",
                    "findings": [
                        {
                            "location": "env/DB_PASSWORD",
                            "ai_context": "Plain-text DB password leaks credentials.",
                            "recommendation": "Use Kubernetes Secret with encryption at rest.",
                        }
                    ],
                },
            }
        )

        with patch("vlamguard.ai.context.httpx.AsyncClient") as mock_client_cls:
            mock_client_cls.return_value = _mock_async_client_for_payload(payload)

            ai_context, hardening_recs, secrets_ai_data = await get_security_ai_context(
                manifests_metadata=[],
                policy_results=[],
                secrets_result=None,
                environment="production",
            )

        assert ai_context is not None
        assert len(hardening_recs) == 1
        assert hardening_recs[0].category == "supply_chain"
        assert secrets_ai_data is not None
        assert secrets_ai_data["summary"] == "Database password found."

    @pytest.mark.asyncio
    async def test_timeout_returns_empty_tuple(self):
        """A TimeoutException causes the function to return (None, [], None)."""
        with patch("vlamguard.ai.context.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.post.side_effect = httpx.TimeoutException("timed out")
            mock_client_cls.return_value = mock_client

            ai_context, hardening_recs, secrets_ai_data = await get_security_ai_context(
                manifests_metadata=[],
                policy_results=[],
                secrets_result=None,
                environment="production",
            )

        assert ai_context is None
        assert hardening_recs == []
        assert secrets_ai_data is None

    @pytest.mark.asyncio
    async def test_http_error_returns_empty_tuple(self):
        """An HTTPStatusError causes the function to return (None, [], None)."""
        with patch("vlamguard.ai.context.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.post.side_effect = httpx.HTTPStatusError(
                "500 Internal Server Error",
                request=MagicMock(),
                response=MagicMock(),
            )
            mock_client_cls.return_value = mock_client

            ai_context, hardening_recs, secrets_ai_data = await get_security_ai_context(
                manifests_metadata=[],
                policy_results=[],
                secrets_result=None,
                environment="production",
            )

        assert ai_context is None
        assert hardening_recs == []
        assert secrets_ai_data is None

    @pytest.mark.asyncio
    async def test_invalid_json_content_returns_empty_tuple(self):
        """When AI returns non-JSON content, function returns (None, [], None)."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "this is not json {"}}]
        }

        with patch("vlamguard.ai.context.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value = mock_client

            ai_context, hardening_recs, secrets_ai_data = await get_security_ai_context(
                manifests_metadata=[],
                policy_results=[],
                secrets_result=None,
                environment="staging",
            )

        assert ai_context is None
        assert hardening_recs == []
        assert secrets_ai_data is None

    @pytest.mark.asyncio
    async def test_missing_choices_key_returns_empty_tuple(self):
        """A KeyError on malformed response structure returns (None, [], None)."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"no_choices_here": []}

        with patch("vlamguard.ai.context.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value = mock_client

            ai_context, hardening_recs, secrets_ai_data = await get_security_ai_context(
                manifests_metadata=[],
                policy_results=[],
                secrets_result=None,
                environment="production",
            )

        assert ai_context is None
        assert hardening_recs == []
        assert secrets_ai_data is None

    @pytest.mark.asyncio
    async def test_security_extended_check_ids_are_filtered_from_policy_results(self):
        """Only the 5 security check_ids are forwarded in extended_checks; others are omitted."""
        security_check = _make_policy_result(
            check_id="host_namespace", name="Host Namespace", passed=False, message="hostPID=true"
        )
        regular_check = _make_policy_result(
            check_id="replica_count", name="Replica Count", passed=True, message="3 replicas"
        )
        excessive_caps = _make_policy_result(
            check_id="excessive_capabilities", name="Capabilities", passed=False, message="SYS_ADMIN"
        )

        captured_calls: list[dict] = []

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "choices": [{"message": {"content": json.dumps(_make_ai_response_payload())}}]
        }

        async def capture_post(url, *, headers, json):  # noqa: A002
            captured_calls.append(json)
            return mock_response

        with patch("vlamguard.ai.context.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.post.side_effect = capture_post
            mock_client_cls.return_value = mock_client

            await get_security_ai_context(
                manifests_metadata=[],
                policy_results=[security_check, regular_check, excessive_caps],
                secrets_result=None,
                environment="production",
            )

        sent_user_content = json.loads(captured_calls[0]["messages"][1]["content"])
        # All 3 checks appear in the top-level policy_results
        assert len(sent_user_content["policy_results"]) == 3
        # Only the 2 security checks appear in extended_checks
        ext_ids = {c["check_id"] for c in sent_user_content["security_scan"]["extended_checks"]}
        assert ext_ids == {"host_namespace", "excessive_capabilities"}
        assert "replica_count" not in ext_ids

    @pytest.mark.asyncio
    async def test_always_uses_security_system_prompt(self):
        """get_security_ai_context always uses the security system prompt regardless of inputs."""
        captured_messages: list[list] = []

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "choices": [{"message": {"content": json.dumps(_make_ai_response_payload())}}]
        }

        async def capture_post(url, *, headers, json):  # noqa: A002
            captured_messages.append(json["messages"])
            return mock_response

        with patch("vlamguard.ai.context.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.post.side_effect = capture_post
            mock_client_cls.return_value = mock_client

            await get_security_ai_context(
                manifests_metadata=[],
                policy_results=[],
                secrets_result=None,
                environment="production",
            )

        system_content = captured_messages[0][0]["content"]
        assert "security analyst" in system_content
        assert "hardening_recommendations" in system_content

    @pytest.mark.asyncio
    async def test_secrets_result_populates_security_scan_payload(self):
        """When secrets_result is provided, user_data.security_scan.secrets is populated correctly."""
        secret_finding = SecretFinding(
            severity="critical",
            type="github_token",
            location="env/GITHUB_TOKEN",
            pattern="github_token",
            detection="deterministic",
        )
        secrets_result = SecretsDetectionResult(
            total_suspects=1,
            confirmed_secrets=1,
            false_positives=0,
            hard_blocks=[secret_finding],
            soft_risks=[],
        )

        captured_calls: list[dict] = []

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "choices": [{"message": {"content": json.dumps(_make_ai_response_payload())}}]
        }

        async def capture_post(url, *, headers, json):  # noqa: A002
            captured_calls.append(json)
            return mock_response

        with patch("vlamguard.ai.context.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.post.side_effect = capture_post
            mock_client_cls.return_value = mock_client

            await get_security_ai_context(
                manifests_metadata=[],
                policy_results=[],
                secrets_result=secrets_result,
                environment="production",
            )

        sent_user_content = json.loads(captured_calls[0]["messages"][1]["content"])
        assert "security_scan" in sent_user_content
        secrets_block = sent_user_content["security_scan"]["secrets"]
        assert secrets_block["total_suspects"] == 1
        assert secrets_block["confirmed_secrets"] == 1
        assert len(secrets_block["findings"]) == 1
        assert secrets_block["findings"][0]["type"] == "github_token"
        assert secrets_block["findings"][0]["location"] == "env/GITHUB_TOKEN"
