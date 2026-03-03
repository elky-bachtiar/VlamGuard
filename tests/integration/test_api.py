"""Integration tests for the FastAPI API endpoint."""

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from vlamguard.main import app


@pytest.fixture
def client():
    return TestClient(app)


def _mock_manifests_clean():
    return [
        {
            "kind": "Deployment",
            "metadata": {"name": "web", "namespace": "production"},
            "spec": {
                "replicas": 3,
                "template": {
                    "spec": {
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


class TestAnalyzeEndpoint:
    def test_clean_deploy_returns_200(self, client):
        with patch("vlamguard.analyze.render_chart", return_value=_mock_manifests_clean()):
            with patch("vlamguard.analyze.get_ai_context", new_callable=AsyncMock, return_value=None):
                response = client.post(
                    "/api/v1/analyze",
                    json={
                        "chart": "./my-chart",
                        "values": {"replicaCount": 3},
                        "environment": "production",
                        "skip_ai": True,
                    },
                )

        assert response.status_code == 200
        data = response.json()
        assert data["blocked"] is False
        assert data["risk_score"] == 0
        assert data["risk_level"] == "low"
        assert isinstance(data["policy_checks"], list)

    def test_missing_required_fields_returns_422(self, client):
        response = client.post("/api/v1/analyze", json={"chart": "./chart"})
        assert response.status_code == 422

    def test_evident_risk_returns_blocked(self, client):
        manifests = [
            {
                "kind": "Deployment",
                "metadata": {"name": "web"},
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
            with patch("vlamguard.analyze.get_ai_context", new_callable=AsyncMock, return_value=None):
                response = client.post(
                    "/api/v1/analyze",
                    json={
                        "chart": "./chart",
                        "values": {},
                        "environment": "production",
                        "skip_ai": True,
                    },
                )

        assert response.status_code == 200
        data = response.json()
        assert data["blocked"] is True
        assert data["risk_score"] == 100

    def test_response_shape(self, client):
        with patch("vlamguard.analyze.render_chart", return_value=_mock_manifests_clean()):
            with patch("vlamguard.analyze.get_ai_context", new_callable=AsyncMock, return_value=None):
                response = client.post(
                    "/api/v1/analyze",
                    json={
                        "chart": "./chart",
                        "values": {},
                        "environment": "production",
                        "skip_ai": True,
                    },
                )

        data = response.json()
        assert "risk_score" in data
        assert "risk_level" in data
        assert "blocked" in data
        assert "hard_blocks" in data
        assert "policy_checks" in data
        assert "ai_context" in data
        assert "metadata" in data
