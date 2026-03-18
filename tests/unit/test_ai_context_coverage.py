# tests/unit/test_ai_context_coverage.py
"""Coverage tests for vlamguard/ai/context.py — targeting uncovered lines.

Covers:
  48-50, 52, 55-57    _strip_js_comments (escaped chars, toggle quotes, // comments)
  72                   _normalise_ai_payload summary dict → string
  77-89                _normalise_ai_payload rollback_suggestion dict → string
  91                   _normalise_ai_payload rollback_suggestion list → string
  96                   _normalise_ai_payload yaml_snippet dict → JSON string
  99-102               _normalise_ai_payload remove unexpected keys from recs
  106                  _normalise_ai_payload missing impact_analysis
  115                  _normalise_ai_payload impact_analysis severity mapping
  120, 122             _normalise_ai_payload hardening_recommendations impact/effort mapping
  125, 127             _normalise_ai_payload yaml_hint dict/list → JSON string
  163                  _serialize_external_findings
  215                  external_findings in user_data
  280-281              schema validation failure (returns None)
  288-289              HTTP error path
  343                  external_findings in security AI user_data
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from vlamguard.ai.context import (
    _normalise_ai_payload,
    _serialize_external_findings,
    _strip_js_comments,
    _strip_markdown_fences,
    get_ai_context,
    get_security_ai_context,
)
from vlamguard.models.response import (
    ExternalFinding,
    PolicyCheckResult,
    SecretFinding,
    SecretsDetectionResult,
)


# ---------------------------------------------------------------------------
# _strip_js_comments
# ---------------------------------------------------------------------------


class TestStripJsComments:
    def test_removes_line_comment(self):
        text = '{"key": "value"} // comment'
        result = _strip_js_comments(text)
        assert result == '{"key": "value"} '

    def test_preserves_url_in_string(self):
        text = '{"url": "https://example.com"}'
        result = _strip_js_comments(text)
        assert result == text

    def test_handles_escaped_quote_in_string(self):
        text = '{"key": "val\\"ue"}'
        result = _strip_js_comments(text)
        assert result == text

    def test_removes_comment_after_string(self):
        text = '{"key": "value"}\n// this is a comment\n{"next": true}'
        result = _strip_js_comments(text)
        assert "// this is a comment" not in result
        assert '{"next": true}' in result

    def test_multiline_with_comments(self):
        text = '{\n  "a": 1, // inline comment\n  "b": 2\n}'
        result = _strip_js_comments(text)
        parsed = json.loads(result)
        assert parsed == {"a": 1, "b": 2}

    def test_empty_string(self):
        assert _strip_js_comments("") == ""

    def test_no_comments(self):
        text = '{"key": "value"}'
        assert _strip_js_comments(text) == text


# ---------------------------------------------------------------------------
# _normalise_ai_payload
# ---------------------------------------------------------------------------


class TestNormaliseAiPayload:
    def test_summary_dict_with_message(self):
        data = {
            "summary": {"status": "ok", "message": "Everything is fine"},
            "rollback_suggestion": "rollback",
            "recommendations": [],
            "impact_analysis": [],
        }
        result = _normalise_ai_payload(data)
        assert result["summary"] == "Everything is fine"

    def test_summary_dict_without_message(self):
        data = {
            "summary": {"status": "ok"},
            "rollback_suggestion": "rollback",
            "recommendations": [],
            "impact_analysis": [],
        }
        result = _normalise_ai_payload(data)
        # Should fall back to json.dumps
        assert "status" in result["summary"]

    def test_rollback_suggestion_dict_with_strategy_and_steps(self):
        data = {
            "summary": "Test",
            "rollback_suggestion": {
                "strategy": "helm rollback",
                "message": "Revert to last known good",
                "steps": [
                    "Step 1",
                    {"command": "helm rollback", "description": "Revert release"},
                    {"command": "kubectl get pods"},
                ],
            },
            "recommendations": [],
            "impact_analysis": [],
        }
        result = _normalise_ai_payload(data)
        rs = result["rollback_suggestion"]
        assert "helm rollback" in rs
        assert "Revert to last known good" in rs
        assert "Step 1" in rs
        assert "Revert release" in rs

    def test_rollback_suggestion_dict_empty_parts(self):
        data = {
            "summary": "Test",
            "rollback_suggestion": {"other_key": "value"},
            "recommendations": [],
            "impact_analysis": [],
        }
        result = _normalise_ai_payload(data)
        # Empty parts → json.dumps fallback
        assert "other_key" in result["rollback_suggestion"]

    def test_rollback_suggestion_list(self):
        data = {
            "summary": "Test",
            "rollback_suggestion": ["step 1", "step 2"],
            "recommendations": [],
            "impact_analysis": [],
        }
        result = _normalise_ai_payload(data)
        assert result["rollback_suggestion"] == "step 1 step 2"

    def test_recommendation_yaml_snippet_dict(self):
        data = {
            "summary": "Test",
            "rollback_suggestion": "rollback",
            "recommendations": [
                {
                    "action": "Fix it",
                    "reason": "Security",
                    "resource": "Deployment/web",
                    "yaml_snippet": {"securityContext": {"runAsNonRoot": True}},
                }
            ],
            "impact_analysis": [],
        }
        result = _normalise_ai_payload(data)
        snippet = result["recommendations"][0]["yaml_snippet"]
        assert isinstance(snippet, str)
        assert "runAsNonRoot" in snippet

    def test_recommendation_removes_unexpected_keys(self):
        data = {
            "summary": "Test",
            "rollback_suggestion": "rollback",
            "recommendations": [
                {
                    "action": "Fix it",
                    "reason": "Security",
                    "resource": "Deployment/web",
                    "unexpected_key": "should be removed",
                    "another_bad_key": 42,
                }
            ],
            "impact_analysis": [],
        }
        result = _normalise_ai_payload(data)
        rec = result["recommendations"][0]
        assert "unexpected_key" not in rec
        assert "another_bad_key" not in rec
        assert "action" in rec

    def test_missing_impact_analysis_added(self):
        data = {
            "summary": "Test",
            "rollback_suggestion": "rollback",
            "recommendations": [],
        }
        result = _normalise_ai_payload(data)
        assert result["impact_analysis"] == []

    def test_impact_analysis_severity_mapping(self):
        data = {
            "summary": "Test",
            "rollback_suggestion": "rollback",
            "recommendations": [],
            "impact_analysis": [
                {"severity": "critical", "resource": "Deployment/web", "description": "Bad"},
                {"severity": "info", "resource": "Service/api", "description": "Info"},
                {"severity": "warning", "resource": "Pod/test", "description": "Warn"},
            ],
        }
        result = _normalise_ai_payload(data)
        assert result["impact_analysis"][0]["severity"] == "high"
        assert result["impact_analysis"][1]["severity"] == "low"
        assert result["impact_analysis"][2]["severity"] == "medium"

    def test_hardening_recommendations_impact_effort_mapping(self):
        data = {
            "summary": "Test",
            "rollback_suggestion": "rollback",
            "recommendations": [],
            "impact_analysis": [],
            "hardening_recommendations": [
                {"impact": "critical", "effort": "none", "action": "Fix"},
                {"impact": "warning", "effort": "info", "action": "Warn"},
            ],
        }
        result = _normalise_ai_payload(data)
        assert result["hardening_recommendations"][0]["impact"] == "high"
        assert result["hardening_recommendations"][0]["effort"] == "low"
        assert result["hardening_recommendations"][1]["impact"] == "medium"
        assert result["hardening_recommendations"][1]["effort"] == "low"

    def test_hardening_yaml_hint_dict(self):
        data = {
            "summary": "Test",
            "rollback_suggestion": "rollback",
            "recommendations": [],
            "impact_analysis": [],
            "hardening_recommendations": [
                {"action": "Fix", "yaml_hint": {"key": "value"}},
            ],
        }
        result = _normalise_ai_payload(data)
        hint = result["hardening_recommendations"][0]["yaml_hint"]
        assert isinstance(hint, str)
        assert "key" in hint

    def test_hardening_yaml_hint_list(self):
        data = {
            "summary": "Test",
            "rollback_suggestion": "rollback",
            "recommendations": [],
            "impact_analysis": [],
            "hardening_recommendations": [
                {"action": "Fix", "yaml_hint": ["item1", "item2"]},
            ],
        }
        result = _normalise_ai_payload(data)
        hint = result["hardening_recommendations"][0]["yaml_hint"]
        assert isinstance(hint, str)
        assert "item1" in hint


# ---------------------------------------------------------------------------
# _serialize_external_findings
# ---------------------------------------------------------------------------


class TestSerializeExternalFindings:
    def test_serializes_findings(self):
        findings = [
            ExternalFinding(
                tool="kube-score",
                check_id="container-resources",
                severity="warning",
                message="No resource limits",
                resource="Deployment/web",
            ),
        ]
        result = _serialize_external_findings(findings)
        assert len(result) == 1
        assert result[0]["tool"] == "kube-score"
        assert result[0]["resource"] == "Deployment/web"


# ---------------------------------------------------------------------------
# get_ai_context — error paths
# ---------------------------------------------------------------------------


def _make_mock_client(post_side_effect=None, post_return_value=None):
    """Helper to create a mock httpx.AsyncClient."""
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    if post_side_effect:
        mock_client.post.side_effect = post_side_effect
    elif post_return_value:
        mock_client.post.return_value = post_return_value
    return mock_client


class TestGetAiContextHTTPError:
    @pytest.mark.asyncio
    async def test_http_error_returns_none(self):
        with patch("vlamguard.ai.context.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value = _make_mock_client(
                post_side_effect=httpx.HTTPStatusError(
                    "500 Server Error",
                    request=MagicMock(),
                    response=MagicMock(status_code=500),
                )
            )
            result = await get_ai_context(
                manifests_metadata=[],
                policy_results=[],
                environment="production",
            )
        assert result is None


class TestGetAiContextSchemaValidationFailure:
    @pytest.mark.asyncio
    async def test_schema_validation_failure_returns_none(self):
        """AI returns valid JSON but fails schema validation → returns None."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": '{"invalid_key": "no summary"}'}}]
        }
        mock_response.raise_for_status = MagicMock()
        mock_response.text = '{"invalid_key": "no summary"}'

        with patch("vlamguard.ai.context.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value = _make_mock_client(post_return_value=mock_response)
            result = await get_ai_context(
                manifests_metadata=[{"kind": "Deployment", "name": "web"}],
                policy_results=[],
                environment="production",
            )
        assert result is None


class TestGetAiContextWithExternalFindings:
    @pytest.mark.asyncio
    async def test_external_findings_included_in_request(self):
        """When external_findings are passed, they appear in user_data."""
        valid_ai_json = json.dumps({
            "summary": "Analysis complete.",
            "impact_analysis": [],
            "recommendations": [],
            "rollback_suggestion": "No rollback needed.",
        })
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": valid_ai_json}}]
        }
        mock_response.raise_for_status = MagicMock()

        external = [
            ExternalFinding(
                tool="kube-score",
                check_id="resource-limits",
                severity="warning",
                message="No limits",
                resource="Deployment/web",
            ),
        ]

        captured_body = {}

        async def capture_post(url, **kwargs):
            captured_body.update(kwargs.get("json", {}))
            return mock_response

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.post.side_effect = capture_post

        with patch("vlamguard.ai.context.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value = mock_client
            result = await get_ai_context(
                manifests_metadata=[{"kind": "Deployment", "name": "web"}],
                policy_results=[],
                environment="production",
                external_findings=external,
            )

        assert result is not None
        # Verify external findings were included in the user message
        user_content = json.loads(captured_body["messages"][1]["content"])
        assert "external_tool_findings" in user_content


class TestGetSecurityAiContextWithExternalFindings:
    @pytest.mark.asyncio
    async def test_external_findings_in_security_context(self):
        """External findings are passed through in security AI context."""
        valid_ai_json = json.dumps({
            "summary": "Security analysis done.",
            "impact_analysis": [],
            "recommendations": [],
            "rollback_suggestion": "No rollback needed.",
        })
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": valid_ai_json}}]
        }
        mock_response.raise_for_status = MagicMock()

        external = [
            ExternalFinding(
                tool="polaris",
                check_id="security-context",
                severity="high",
                message="Missing security context",
                resource="Deployment/web",
            ),
        ]

        captured_body = {}

        async def capture_post(url, **kwargs):
            captured_body.update(kwargs.get("json", {}))
            return mock_response

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.post.side_effect = capture_post

        with patch("vlamguard.ai.context.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value = mock_client
            ai_context, hardening, secrets_ai = await get_security_ai_context(
                manifests_metadata=[{"kind": "Deployment", "name": "web"}],
                policy_results=[],
                secrets_result=None,
                environment="production",
                external_findings=external,
            )

        user_content = json.loads(captured_body["messages"][1]["content"])
        assert "external_tool_findings" in user_content
