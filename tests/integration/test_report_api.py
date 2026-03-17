# tests/integration/test_report_api.py
"""Tests for POST /api/v1/report endpoint."""

from unittest.mock import patch, AsyncMock

import pytest
from httpx import AsyncClient, ASGITransport

from vlamguard.main import app
from vlamguard.models.request import ReportRequest


class TestReportRequest:
    def test_extends_analyze_request(self):
        req = ReportRequest(
            chart="./chart",
            values={},
            environment="production",
            create_issues=True,
            create_pr=False,
        )
        assert req.create_issues is True
        assert req.create_pr is False
        assert req.remote == "origin"
        assert req.platform_override is None

    def test_defaults(self):
        req = ReportRequest(
            chart="./chart", values={}, environment="dev",
        )
        assert req.create_issues is False
        assert req.create_pr is False


class TestReportEndpoint:
    @pytest.mark.asyncio
    async def test_endpoint_exists(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/api/v1/report", json={
                "chart": "./nonexistent",
                "values": {},
                "environment": "dev",
            })
            # Should return 400 (chart not found) not 404 (endpoint not found)
            assert response.status_code != 404
