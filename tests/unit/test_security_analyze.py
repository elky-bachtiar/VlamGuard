"""Tests for security scan integration in the analyze pipeline."""

from unittest.mock import AsyncMock, patch

import pytest

from vlamguard.analyze import analyze
from vlamguard.models.request import AnalyzeRequest


def _manifest_with_secret():
    return [
        {
            "kind": "Deployment",
            "metadata": {"name": "backend", "namespace": "production"},
            "spec": {
                "replicas": 2,
                "template": {
                    "spec": {
                        "automountServiceAccountToken": False,
                        "securityContext": {"runAsUser": 1000, "runAsGroup": 1000},
                        "affinity": {
                            "podAntiAffinity": {
                                "preferredDuringSchedulingIgnoredDuringExecution": [],
                            },
                        },
                        "containers": [
                            {
                                "name": "api",
                                "image": "myapp:1.5.2",
                                "imagePullPolicy": "Always",
                                "securityContext": {
                                    "runAsNonRoot": True,
                                    "privileged": False,
                                    "readOnlyRootFilesystem": True,
                                },
                                "livenessProbe": {"httpGet": {"path": "/health", "port": 8080}},
                                "readinessProbe": {"httpGet": {"path": "/ready", "port": 8080}},
                                "resources": {
                                    "requests": {"cpu": "100m", "memory": "128Mi"},
                                    "limits": {"cpu": "500m", "memory": "256Mi"},
                                },
                                "env": [
                                    {
                                        "name": "DATABASE_URL",
                                        "value": "postgresql://admin:SuperSecret123!@postgres:5432/myapp",
                                    }
                                ],
                            }
                        ],
                    }
                },
            },
        }
    ]


def _clean_manifest():
    return [
        {
            "kind": "Deployment",
            "metadata": {"name": "web", "namespace": "production"},
            "spec": {
                "replicas": 2,
                "template": {
                    "spec": {
                        "automountServiceAccountToken": False,
                        "securityContext": {"runAsUser": 1000, "runAsGroup": 1000},
                        "affinity": {
                            "podAntiAffinity": {
                                "preferredDuringSchedulingIgnoredDuringExecution": [],
                            },
                        },
                        "containers": [
                            {
                                "name": "app",
                                "image": "nginx:1.25.3",
                                "imagePullPolicy": "Always",
                                "securityContext": {
                                    "runAsNonRoot": True,
                                    "privileged": False,
                                    "readOnlyRootFilesystem": True,
                                },
                                "livenessProbe": {"httpGet": {"path": "/healthz", "port": 8080}},
                                "readinessProbe": {"httpGet": {"path": "/ready", "port": 8080}},
                                "resources": {
                                    "requests": {"cpu": "100m", "memory": "128Mi"},
                                    "limits": {"cpu": "500m", "memory": "256Mi"},
                                },
                            }
                        ],
                    }
                },
            },
        }
    ]


class TestSecurityScanPipeline:
    @pytest.mark.asyncio
    async def test_security_scan_enabled_by_default(self):
        with patch("vlamguard.analyze.render_chart", return_value=_clean_manifest()):
            with patch("vlamguard.analyze.get_security_ai_context", new_callable=AsyncMock, return_value=(None, [], None)):
                request = AnalyzeRequest(
                    chart="./chart", values={}, environment="production", skip_ai=True,
                )
                response = await analyze(request)

        assert response.security is not None
        assert response.security_grade is not None

    @pytest.mark.asyncio
    async def test_security_scan_disabled(self):
        with patch("vlamguard.analyze.render_chart", return_value=_clean_manifest()):
            with patch("vlamguard.analyze.get_ai_context", new_callable=AsyncMock, return_value=None):
                request = AnalyzeRequest(
                    chart="./chart", values={}, environment="production",
                    skip_ai=True, security_scan=False,
                )
                response = await analyze(request)

        assert response.security is None
        assert response.security_grade is None

    @pytest.mark.asyncio
    async def test_secrets_detected_in_production(self):
        with patch("vlamguard.analyze.render_chart", return_value=_manifest_with_secret()):
            with patch("vlamguard.analyze.get_security_ai_context", new_callable=AsyncMock, return_value=(None, [], None)):
                request = AnalyzeRequest(
                    chart="./chart",
                    values={"database": {"password": "SuperSecret123!"}},
                    environment="production",
                    skip_ai=True,
                )
                response = await analyze(request)

        assert response.security is not None
        sd = response.security.secrets_detection
        assert sd is not None
        assert sd.confirmed_secrets > 0
        assert len(sd.hard_blocks) > 0

    @pytest.mark.asyncio
    async def test_secrets_detected_in_dev_are_soft_risks(self):
        with patch("vlamguard.analyze.render_chart", return_value=_manifest_with_secret()):
            with patch("vlamguard.analyze.get_security_ai_context", new_callable=AsyncMock, return_value=(None, [], None)):
                request = AnalyzeRequest(
                    chart="./chart", values={}, environment="dev", skip_ai=True,
                )
                response = await analyze(request)

        assert response.security is not None
        sd = response.security.secrets_detection
        assert sd is not None
        assert sd.confirmed_secrets == 0
        assert len(sd.soft_risks) > 0

    @pytest.mark.asyncio
    async def test_security_grade_present(self):
        with patch("vlamguard.analyze.render_chart", return_value=_clean_manifest()):
            with patch("vlamguard.analyze.get_security_ai_context", new_callable=AsyncMock, return_value=(None, [], None)):
                request = AnalyzeRequest(
                    chart="./chart", values={}, environment="production", skip_ai=True,
                )
                response = await analyze(request)

        assert response.security_grade is not None
        assert response.security_grade.value in ("A", "B", "C", "D", "F")

    @pytest.mark.asyncio
    async def test_extended_checks_in_security_section(self):
        with patch("vlamguard.analyze.render_chart", return_value=_clean_manifest()):
            with patch("vlamguard.analyze.get_security_ai_context", new_callable=AsyncMock, return_value=(None, [], None)):
                request = AnalyzeRequest(
                    chart="./chart", values={}, environment="production", skip_ai=True,
                )
                response = await analyze(request)

        assert response.security is not None
        ext_ids = {c.check_id for c in response.security.extended_checks}
        # Our clean manifest is a Deployment so workload checks apply
        assert "service_account_token" in ext_ids

    @pytest.mark.asyncio
    async def test_production_secret_blocks_pipeline(self):
        """Production secrets must set blocked=True and risk_score=100."""
        with patch("vlamguard.analyze.render_chart", return_value=_manifest_with_secret()):
            with patch("vlamguard.analyze.get_security_ai_context", new_callable=AsyncMock, return_value=(None, [], None)):
                request = AnalyzeRequest(
                    chart="./chart",
                    values={},
                    environment="production",
                    skip_ai=True,
                )
                response = await analyze(request)

        assert response.blocked is True
        assert response.risk_score == 100
        assert any("Secrets Detection" in hb for hb in response.hard_blocks)

    @pytest.mark.asyncio
    async def test_dev_secret_adds_to_soft_score(self):
        """Non-production secrets from hard patterns add +30 to soft score."""
        with patch("vlamguard.analyze.render_chart", return_value=_manifest_with_secret()):
            with patch("vlamguard.analyze.get_security_ai_context", new_callable=AsyncMock, return_value=(None, [], None)):
                request = AnalyzeRequest(
                    chart="./chart",
                    values={},
                    environment="dev",
                    skip_ai=True,
                )
                response = await analyze(request)

        # Should not be blocked by secrets alone in dev
        assert response.risk_score > 0
        # Secrets add +30 per hard-pattern finding (database_url + generic_password_env)
        sd = response.security.secrets_detection
        assert sd.confirmed_secrets == 0
        assert len(sd.soft_risks) > 0

    @pytest.mark.asyncio
    async def test_response_shape_with_security(self):
        with patch("vlamguard.analyze.render_chart", return_value=_clean_manifest()):
            with patch("vlamguard.analyze.get_security_ai_context", new_callable=AsyncMock, return_value=(None, [], None)):
                request = AnalyzeRequest(
                    chart="./chart", values={}, environment="production", skip_ai=True,
                )
                response = await analyze(request)

        data = response.model_dump()
        assert "security_grade" in data
        assert "security" in data
        assert "secrets_detection" in data["security"]
        assert "extended_checks" in data["security"]
        assert "hardening_recommendations" in data["security"]
