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
                                    "image": "docker.io/library/nginx:1.25.3",
                                    "imagePullPolicy": "Always",
                                    "securityContext": {
                                        "runAsNonRoot": True,
                                        "privileged": False,
                                        "readOnlyRootFilesystem": True,
                                        "allowPrivilegeEscalation": False,
                                        "capabilities": {"drop": ["ALL"]},
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
                            "automountServiceAccountToken": False,
                            "securityContext": {"runAsUser": 1000, "runAsGroup": 1000},
                            "containers": [
                                {
                                    "name": "app",
                                    "image": "docker.io/library/nginx:1.25.3",
                                    "imagePullPolicy": "Always",
                                    "securityContext": {
                                        "runAsNonRoot": True,
                                        "privileged": False,
                                        "readOnlyRootFilesystem": True,
                                        "allowPrivilegeEscalation": False,
                                        "capabilities": {"drop": ["ALL"]},
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
        # 30 (replica_count) is the only failure
        assert response.risk_score == 30
        assert response.risk_level.value == "low"

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

    @pytest.mark.asyncio
    async def test_non_security_ai_path_calls_get_ai_context(self):
        """When security_scan=False and skip_ai=False, get_ai_context (not get_security_ai_context) is called."""
        from vlamguard.models.response import AIContext, ImpactItem

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
                            ],
                        }
                    },
                },
            }
        ]

        ai_result = AIContext(
            summary="Low risk change.",
            impact_analysis=[ImpactItem(severity="low", resource="Deployment/web", description="Minor update.")],
            recommendations=["No action required."],
            rollback_suggestion="kubectl rollout undo",
        )

        mock_ai_context = AsyncMock(return_value=ai_result)
        mock_security_ai_context = AsyncMock(return_value=(None, [], None))

        with patch("vlamguard.analyze.render_chart", return_value=manifests):
            with patch("vlamguard.analyze.get_ai_context", mock_ai_context):
                with patch("vlamguard.analyze.get_security_ai_context", mock_security_ai_context):
                    request = AnalyzeRequest(
                        chart="./chart",
                        values={},
                        environment="production",
                        skip_ai=False,
                        security_scan=False,
                    )
                    response = await analyze(request)

        # get_ai_context must have been called, get_security_ai_context must NOT
        mock_ai_context.assert_called_once()
        mock_security_ai_context.assert_not_called()

        # AI context propagates to the response
        assert response.ai_context is not None
        assert response.ai_context.summary == "Low risk change."

    @pytest.mark.asyncio
    async def test_non_security_ai_path_returns_none_on_failure(self):
        """When get_ai_context returns None (e.g. timeout), ai_context in response is None."""
        manifests = [
            {
                "kind": "Deployment",
                "metadata": {"name": "web"},
                "spec": {
                    "replicas": 2,
                    "template": {
                        "spec": {
                            "containers": [
                                {
                                    "name": "app",
                                    "image": "nginx:1.25.3",
                                    "securityContext": {"runAsNonRoot": True, "privileged": False},
                                }
                            ]
                        }
                    },
                },
            }
        ]

        with patch("vlamguard.analyze.render_chart", return_value=manifests):
            with patch("vlamguard.analyze.get_ai_context", new_callable=AsyncMock, return_value=None):
                request = AnalyzeRequest(
                    chart="./chart",
                    values={},
                    environment="staging",
                    skip_ai=False,
                    security_scan=False,
                )
                response = await analyze(request)

        assert response.ai_context is None

    @pytest.mark.asyncio
    async def test_ai_context_applied_to_matching_secrets_findings(self):
        """When secrets_ai_data has findings matching secret locations, AI context is merged into SecretFindings."""
        from vlamguard.models.response import SecretFinding, SecretsDetectionResult

        manifests = [
            {
                "kind": "Deployment",
                "metadata": {"name": "backend"},
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
                                    "image": "myapp:1.0.0",
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
                                            "value": "postgresql://admin:secret@postgres:5432/myapp",
                                        }
                                    ],
                                }
                            ],
                        }
                    },
                },
            }
        ]

        target_location = "Deployment/backend → container/api → env/DATABASE_URL"
        mock_secret_finding = SecretFinding(
            severity="critical",
            type="database_url",
            location=target_location,
            pattern="database_url",
            detection="deterministic",
        )
        mock_secrets_result = SecretsDetectionResult(
            total_suspects=1,
            confirmed_secrets=1,
            false_positives=0,
            hard_blocks=[mock_secret_finding],
            soft_risks=[],
        )

        # secrets_ai_data returned by AI that matches the location
        secrets_ai_data = {
            "summary": "Hardcoded DB credential found.",
            "findings": [
                {
                    "location": target_location,
                    "ai_context": "This credential grants full database access.",
                    "recommendation": "Use a Kubernetes Secret and reference it via secretKeyRef.",
                    "effort": "medium",
                }
            ],
        }

        with patch("vlamguard.analyze.render_chart", return_value=manifests):
            with patch("vlamguard.analyze.scan_secrets", return_value=mock_secrets_result):
                with patch(
                    "vlamguard.analyze.get_security_ai_context",
                    new_callable=AsyncMock,
                    return_value=(None, [], secrets_ai_data),
                ):
                    request = AnalyzeRequest(
                        chart="./chart",
                        values={},
                        environment="production",
                        skip_ai=False,
                        security_scan=True,
                    )
                    response = await analyze(request)

        assert response.security is not None
        sd = response.security.secrets_detection
        assert sd is not None
        assert sd.summary == "Hardcoded DB credential found."

        # The AI context must be merged into the matching SecretFinding
        matched_finding = sd.hard_blocks[0]
        assert matched_finding.ai_context == "This credential grants full database access."
        assert matched_finding.recommendation == "Use a Kubernetes Secret and reference it via secretKeyRef."
        assert matched_finding.effort == "medium"

    @pytest.mark.asyncio
    async def test_ai_context_not_applied_when_no_secrets_result(self):
        """When secrets_result is None, the AI context-to-secrets merge path is safely skipped."""
        manifests = [
            {
                "kind": "Deployment",
                "metadata": {"name": "web"},
                "spec": {
                    "replicas": 2,
                    "template": {
                        "spec": {
                            "containers": [
                                {
                                    "name": "app",
                                    "image": "nginx:1.25.3",
                                    "securityContext": {"runAsNonRoot": True, "privileged": False},
                                }
                            ]
                        }
                    },
                },
            }
        ]

        with patch("vlamguard.analyze.render_chart", return_value=manifests):
            with patch("vlamguard.analyze.get_ai_context", new_callable=AsyncMock, return_value=None):
                request = AnalyzeRequest(
                    chart="./chart",
                    values={},
                    environment="staging",
                    skip_ai=False,
                    security_scan=False,
                )
                # Must not raise — the merge branch is guarded by `if secrets_result and secrets_ai_data`
                response = await analyze(request)

        assert response.security is None

    @pytest.mark.asyncio
    async def test_ai_context_applied_to_soft_risk_findings(self):
        """AI context is also applied to soft_risks when the location matches."""
        from vlamguard.models.response import SecretFinding, SecretsDetectionResult

        manifests = [
            {
                "kind": "Deployment",
                "metadata": {"name": "worker"},
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
                                    "name": "job",
                                    "image": "worker:2.0.0",
                                    "imagePullPolicy": "Always",
                                    "securityContext": {
                                        "runAsNonRoot": True,
                                        "privileged": False,
                                        "readOnlyRootFilesystem": True,
                                    },
                                    "livenessProbe": {"httpGet": {"path": "/health", "port": 8080}},
                                    "readinessProbe": {"httpGet": {"path": "/ready", "port": 8080}},
                                    "resources": {
                                        "requests": {"cpu": "50m", "memory": "64Mi"},
                                        "limits": {"cpu": "200m", "memory": "128Mi"},
                                    },
                                    "env": [
                                        {"name": "API_KEY", "value": "somevalue"},
                                    ],
                                }
                            ],
                        }
                    },
                },
            }
        ]

        soft_location = "Deployment/worker → container/job → env/API_KEY"
        soft_finding = SecretFinding(
            severity="medium",
            type="suspicious_key_name",
            location=soft_location,
            pattern="suspicious_key_name",
            detection="deterministic",
        )
        mock_secrets_result = SecretsDetectionResult(
            total_suspects=1,
            confirmed_secrets=0,
            false_positives=0,
            hard_blocks=[],
            soft_risks=[soft_finding],
        )

        secrets_ai_data = {
            "summary": "Suspicious key name found.",
            "findings": [
                {
                    "location": soft_location,
                    "ai_context": "This key name suggests an API credential.",
                    "recommendation": "Store in a Kubernetes Secret.",
                    "effort": "low",
                }
            ],
        }

        with patch("vlamguard.analyze.render_chart", return_value=manifests):
            with patch("vlamguard.analyze.scan_secrets", return_value=mock_secrets_result):
                with patch(
                    "vlamguard.analyze.get_security_ai_context",
                    new_callable=AsyncMock,
                    return_value=(None, [], secrets_ai_data),
                ):
                    request = AnalyzeRequest(
                        chart="./chart",
                        values={},
                        environment="production",
                        skip_ai=False,
                        security_scan=True,
                    )
                    response = await analyze(request)

        sd = response.security.secrets_detection
        assert sd.summary == "Suspicious key name found."
        soft = sd.soft_risks[0]
        assert soft.ai_context == "This key name suggests an API credential."
        assert soft.recommendation == "Store in a Kubernetes Secret."
        assert soft.effort == "low"
