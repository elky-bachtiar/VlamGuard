"""Additional coverage tests for vlamguard/main.py — targeting uncovered lines.

Uncovered before this file:
  27-28  analyze_endpoint — HelmRenderError path raises HTTP 400
"""

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from vlamguard.engine.helm import HelmRenderError
from vlamguard.main import app

client = TestClient(app)


# ---------------------------------------------------------------------------
# /health endpoint
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    def test_health_returns_200(self):
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_returns_ok_status(self):
        response = client.get("/health")
        assert response.json() == {"status": "ok"}

    def test_health_content_type_is_json(self):
        response = client.get("/health")
        assert "application/json" in response.headers["content-type"]


# ---------------------------------------------------------------------------
# /api/v1/analyze — HelmRenderError → HTTP 400 (lines 27-28)
# ---------------------------------------------------------------------------


class TestAnalyzeEndpointHelmError:
    def test_helm_render_error_returns_400(self):
        """When analyze() raises HelmRenderError the endpoint returns HTTP 400."""
        with patch(
            "vlamguard.main.analyze",
            new_callable=AsyncMock,
            side_effect=HelmRenderError("chart directory not found"),
        ):
            response = client.post(
                "/api/v1/analyze",
                json={
                    "chart": "/nonexistent/chart",
                    "values": {},
                    "environment": "production",
                    "skip_ai": True,
                },
            )

        assert response.status_code == 400

    def test_helm_render_error_detail_in_response(self):
        """The error detail from HelmRenderError is surfaced in the response body."""
        error_message = "helm template failed (exit 1): chart not found"
        with patch(
            "vlamguard.main.analyze",
            new_callable=AsyncMock,
            side_effect=HelmRenderError(error_message),
        ):
            response = client.post(
                "/api/v1/analyze",
                json={
                    "chart": "/bad/chart",
                    "values": {},
                    "environment": "production",
                    "skip_ai": True,
                },
            )

        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        assert error_message in data["detail"]

    def test_helm_render_error_not_swallowed_as_500(self):
        """HelmRenderError must produce 400, not 500 — it is a client-supplied bad path."""
        with patch(
            "vlamguard.main.analyze",
            new_callable=AsyncMock,
            side_effect=HelmRenderError("helm CLI not found"),
        ):
            response = client.post(
                "/api/v1/analyze",
                json={
                    "chart": "./chart",
                    "values": {},
                    "environment": "staging",
                    "skip_ai": True,
                },
            )

        assert response.status_code != 500
        assert response.status_code == 400

    def test_non_helm_error_propagates_as_500(self):
        """An unexpected generic exception propagates as HTTP 500 (not caught by the handler).

        TestClient re-raises unhandled server exceptions by default. We disable
        that behaviour with raise_server_errors=False to inspect the HTTP status code.
        """
        safe_client = TestClient(app, raise_server_exceptions=False)
        with patch(
            "vlamguard.main.analyze",
            new_callable=AsyncMock,
            side_effect=RuntimeError("unexpected failure"),
        ):
            response = safe_client.post(
                "/api/v1/analyze",
                json={
                    "chart": "./chart",
                    "values": {},
                    "environment": "production",
                    "skip_ai": True,
                },
            )

        assert response.status_code == 500
