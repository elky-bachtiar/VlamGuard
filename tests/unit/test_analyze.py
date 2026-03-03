"""Tests for the core analyze pipeline orchestrator."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vlamguard.analyze import analyze
from vlamguard.models.request import AnalyzeRequest


class TestAnalyzePipeline:
    @pytest.mark.asyncio
    async def test_clean_deploy_passes(self):
        """Scenario 1: Clean deploy with proper config."""
        manifests = [
            {
                "kind": "Deployment",
                "metadata": {"name": "web", "namespace": "production"},
                "spec": {
                    "replicas": 3,
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
                            ]
                        }
                    },
                },
            }
        ]

        with patch("vlamguard.analyze.render_chart", return_value=manifests):
            with patch("vlamguard.analyze.get_security_ai_context", new_callable=AsyncMock, return_value=(None, [], None)):
                request = AnalyzeRequest(chart="./chart", values={}, environment="production")
                response = await analyze(request)

        assert response.blocked is False
        assert response.risk_score == 0
        assert response.risk_level.value == "low"

    @pytest.mark.asyncio
    async def test_evident_risk_blocks(self):
        """Scenario 2: latest tag + privileged -> hard block."""
        manifests = [
            {
                "kind": "Deployment",
                "metadata": {"name": "web", "namespace": "production"},
                "spec": {
                    "replicas": 1,
                    "template": {
                        "spec": {
                            "containers": [
                                {
                                    "name": "app",
                                    "image": "nginx:latest",
                                    "securityContext": {"privileged": True},
                                }
                            ]
                        }
                    },
                },
            }
        ]

        with patch("vlamguard.analyze.render_chart", return_value=manifests):
            with patch("vlamguard.analyze.get_security_ai_context", new_callable=AsyncMock, return_value=(None, [], None)):
                request = AnalyzeRequest(chart="./chart", values={}, environment="production")
                response = await analyze(request)

        assert response.blocked is True
        assert response.risk_score == 100
        assert len(response.hard_blocks) > 0

    @pytest.mark.asyncio
    async def test_subtle_impact_warns(self):
        """Scenario 3: replica 1 in prod, everything else ok -> soft risk."""
        manifests = [
            {
                "kind": "Deployment",
                "metadata": {"name": "web", "namespace": "production"},
                "spec": {
                    "replicas": 1,
                    "template": {
                        "spec": {
                            "securityContext": {"runAsUser": 1000, "runAsGroup": 1000},
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
                            ]
                        }
                    },
                },
            }
        ]

        with patch("vlamguard.analyze.render_chart", return_value=manifests):
            with patch("vlamguard.analyze.get_security_ai_context", new_callable=AsyncMock, return_value=(None, [], None)):
                request = AnalyzeRequest(chart="./chart", values={}, environment="production")
                response = await analyze(request)

        assert response.blocked is False
        # 30 (replica_count) + 10 (service_account_token) = 40
        assert response.risk_score == 40
        assert response.risk_level.value == "medium"

    @pytest.mark.asyncio
    async def test_skip_ai_flag(self):
        """When skip_ai=True, AI is not called."""
        manifests = [
            {
                "kind": "Deployment",
                "metadata": {"name": "web"},
                "spec": {
                    "replicas": 3,
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
                            ]
                        }
                    },
                },
            }
        ]

        mock_ai = AsyncMock(return_value=(None, [], None))
        with patch("vlamguard.analyze.render_chart", return_value=manifests):
            with patch("vlamguard.analyze.get_security_ai_context", mock_ai):
                request = AnalyzeRequest(
                    chart="./chart", values={}, environment="production", skip_ai=True
                )
                await analyze(request)

        mock_ai.assert_not_called()

    @pytest.mark.asyncio
    async def test_skip_external_flag(self):
        """When skip_external=True, external tools are not called."""
        manifests = [
            {
                "kind": "Deployment",
                "metadata": {"name": "web"},
                "spec": {
                    "replicas": 3,
                    "template": {
                        "spec": {
                            "securityContext": {"runAsUser": 1000, "runAsGroup": 1000},
                            "containers": [
                                {
                                    "name": "app",
                                    "image": "nginx:1.25.3",
                                    "securityContext": {
                                        "runAsNonRoot": True,
                                        "privileged": False,
                                        "readOnlyRootFilesystem": True,
                                    },
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
        ]

        mock_ext = MagicMock(return_value=([], None))
        with patch("vlamguard.analyze.render_chart", return_value=manifests):
            with patch("vlamguard.analyze.get_security_ai_context", new_callable=AsyncMock, return_value=(None, [], None)):
                with patch("vlamguard.analyze.run_all_external_tools", mock_ext):
                    request = AnalyzeRequest(
                        chart="./chart", values={}, environment="production",
                        skip_ai=True, skip_external=True,
                    )
                    response = await analyze(request)

        mock_ext.assert_not_called()
        assert response.external_findings == []
        assert response.polaris_score is None

    @pytest.mark.asyncio
    async def test_external_findings_in_response(self):
        """External tool findings are included in the response."""
        from vlamguard.models.response import ExternalFinding

        manifests = [
            {
                "kind": "Deployment",
                "metadata": {"name": "web"},
                "spec": {
                    "replicas": 3,
                    "template": {
                        "spec": {
                            "securityContext": {"runAsUser": 1000, "runAsGroup": 1000},
                            "containers": [
                                {
                                    "name": "app",
                                    "image": "nginx:1.25.3",
                                    "securityContext": {
                                        "runAsNonRoot": True,
                                        "privileged": False,
                                        "readOnlyRootFilesystem": True,
                                    },
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
        ]

        ext_findings = [
            ExternalFinding(tool="kube-score", check_id="test", severity="warning", message="Test finding")
        ]

        with patch("vlamguard.analyze.render_chart", return_value=manifests):
            with patch("vlamguard.analyze.get_security_ai_context", new_callable=AsyncMock, return_value=(None, [], None)):
                with patch("vlamguard.analyze.run_all_external_tools", return_value=(ext_findings, 85)):
                    request = AnalyzeRequest(
                        chart="./chart", values={}, environment="production", skip_ai=True,
                    )
                    response = await analyze(request)

        assert len(response.external_findings) == 1
        assert response.external_findings[0].tool == "kube-score"
        assert response.polaris_score == 85
