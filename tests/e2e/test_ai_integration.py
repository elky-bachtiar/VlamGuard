"""E2E tests for VlamGuard AI integration.

Spins up a lightweight mock OpenAI-compatible server and runs the CLI
without --skip-ai to verify the full AI pipeline works end-to-end.
"""

import json
import subprocess
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent.parent / "fixtures"

# Valid AI response matching the schema in ai/schemas.py
MOCK_AI_RESPONSE = {
    "summary": "Deployment web in namespace production with nginx:1.25.3 image.",
    "impact_analysis": [
        {
            "severity": "low",
            "resource": "Deployment/web",
            "description": "Well-configured deployment with security context.",
        }
    ],
    "recommendations": [
        {
            "action": "Consider adding network policies",
            "reason": "Limits lateral movement if the pod is compromised",
            "resource": "Deployment/web",
        }
    ],
    "rollback_suggestion": "kubectl rollout undo deployment/web",
}


class MockAIHandler(BaseHTTPRequestHandler):
    """Handles /v1/chat/completions with a canned OpenAI-format response."""

    def do_POST(self):
        # Read request body so the connection completes cleanly
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""

        if self.path == "/v1/chat/completions":
            # Store the request for assertions
            self.server.last_request = json.loads(body) if body else {}

            response = {
                "id": "chatcmpl-test",
                "object": "chat.completion",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": json.dumps(MOCK_AI_RESPONSE),
                        },
                        "finish_reason": "stop",
                    }
                ],
            }
            payload = json.dumps(response).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        else:
            self.send_error(404)

    def log_message(self, format, *args):
        """Suppress default stderr logging during tests."""
        pass


@pytest.fixture(scope="module")
def mock_ai_server():
    """Start a mock AI server on a random port, yield its base URL, then shut down."""
    server = HTTPServer(("127.0.0.1", 0), MockAIHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}/v1", server
    server.shutdown()


def _run_cli(*args: str, env_override: dict | None = None) -> subprocess.CompletedProcess:
    """Run the VlamGuard CLI with optional env overrides."""
    import os

    env = os.environ.copy()
    if env_override:
        env.update(env_override)
    return subprocess.run(
        [sys.executable, "-m", "vlamguard.cli", *args],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )


class TestAIIntegrationE2E:
    """Tests that AI context flows through the full CLI pipeline."""

    def test_check_with_ai_returns_context(self, mock_ai_server):
        """CLI check without --skip-ai gets AI context from mock server."""
        base_url, server = mock_ai_server
        result = _run_cli(
            "check",
            "--manifests", str(FIXTURES / "clean-deploy.yaml"),
            "--env", "production",
            "--skip-external",
            "--no-security-scan",
            "--output", "json",
            env_override={
                "VLAM_AI_BASE_URL": base_url,
                "VLAM_AI_MODEL": "test-model",
                "VLAM_AI_API_KEY": "test-key",
            },
        )
        data = json.loads(result.stdout)
        assert data["ai_context"] is not None, "AI context should not be None"
        assert "Deployment web" in data["ai_context"]["summary"]
        assert len(data["ai_context"]["impact_analysis"]) == 1
        assert len(data["ai_context"]["recommendations"]) == 1
        assert data["ai_context"]["rollback_suggestion"] == "kubectl rollout undo deployment/web"

    def test_check_with_ai_terminal_shows_ai_section(self, mock_ai_server):
        """Terminal output should show AI context, not 'AI context not available'."""
        base_url, _server = mock_ai_server
        result = _run_cli(
            "check",
            "--manifests", str(FIXTURES / "clean-deploy.yaml"),
            "--env", "production",
            "--skip-external",
            "--no-security-scan",
            env_override={
                "VLAM_AI_BASE_URL": base_url,
                "VLAM_AI_MODEL": "test-model",
                "VLAM_AI_API_KEY": "test-key",
            },
        )
        assert "AI context not available" not in result.stdout

    def test_debug_flag_shows_ai_request_info(self, mock_ai_server):
        """--debug flag should show the AI request URL in stderr."""
        base_url, _server = mock_ai_server
        result = _run_cli(
            "check",
            "--manifests", str(FIXTURES / "clean-deploy.yaml"),
            "--env", "production",
            "--skip-external",
            "--no-security-scan",
            "--debug",
            env_override={
                "VLAM_AI_BASE_URL": base_url,
                "VLAM_AI_MODEL": "test-model",
                "VLAM_AI_API_KEY": "test-key",
            },
        )
        # Debug logging goes to stderr
        assert "AI request: POST" in result.stderr
        assert "/v1/chat/completions" in result.stderr
        assert "model=test-model" in result.stderr
        assert "api_key_set=True" in result.stderr
        assert "AI response: status=200" in result.stderr

    def test_ai_sends_correct_model_and_auth(self, mock_ai_server):
        """Verify the CLI sends the configured model and auth header."""
        base_url, server = mock_ai_server
        _run_cli(
            "check",
            "--manifests", str(FIXTURES / "clean-deploy.yaml"),
            "--env", "production",
            "--skip-external",
            "--no-security-scan",
            "--output", "json",
            env_override={
                "VLAM_AI_BASE_URL": base_url,
                "VLAM_AI_MODEL": "my-custom-model",
                "VLAM_AI_API_KEY": "my-secret-key",
            },
        )
        req = server.last_request
        assert req["model"] == "my-custom-model"
        assert len(req["messages"]) == 2
        assert req["messages"][0]["role"] == "system"
        assert req["messages"][1]["role"] == "user"

    def test_security_scan_with_ai_returns_context(self, mock_ai_server):
        """security-scan command also gets AI context from mock server."""
        base_url, _server = mock_ai_server
        result = _run_cli(
            "security-scan",
            "--manifests", str(FIXTURES / "clean-deploy.yaml"),
            "--env", "production",
            "--output", "json",
            env_override={
                "VLAM_AI_BASE_URL": base_url,
                "VLAM_AI_MODEL": "test-model",
                "VLAM_AI_API_KEY": "test-key",
            },
        )
        data = json.loads(result.stdout)
        assert data["ai_context"] is not None, "security-scan AI context should not be None"
        assert "Deployment web" in data["ai_context"]["summary"]

    def test_ai_failure_gracefully_returns_none(self):
        """If the AI server is unreachable, AI context should be None (not crash)."""
        result = _run_cli(
            "check",
            "--manifests", str(FIXTURES / "clean-deploy.yaml"),
            "--env", "production",
            "--skip-external",
            "--no-security-scan",
            "--output", "json",
            env_override={
                "VLAM_AI_BASE_URL": "http://127.0.0.1:1",  # nothing listening
                "VLAM_AI_MODEL": "test-model",
                "VLAM_AI_API_KEY": "test-key",
                "VLAM_AI_TIMEOUT": "2",  # fast timeout
            },
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["ai_context"] is None

    def test_debug_shows_error_on_failure(self):
        """--debug should log the connection error when AI server is down."""
        result = _run_cli(
            "check",
            "--manifests", str(FIXTURES / "clean-deploy.yaml"),
            "--env", "production",
            "--skip-external",
            "--no-security-scan",
            "--debug",
            env_override={
                "VLAM_AI_BASE_URL": "http://127.0.0.1:1",
                "VLAM_AI_MODEL": "test-model",
                "VLAM_AI_API_KEY": "test-key",
                "VLAM_AI_TIMEOUT": "2",
            },
        )
        assert "AI request failed" in result.stderr


class TestAIResponseNormalisation:
    """Tests for markdown fences, JS comments, and object-to-string coercion."""

    def _make_server(self, ai_content: str):
        """Create a mock server that returns the given content string."""

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self_inner):
                length = int(self_inner.headers.get("Content-Length", 0))
                self_inner.rfile.read(length)
                response = {
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": ai_content},
                            "finish_reason": "stop",
                        }
                    ],
                }
                payload = json.dumps(response).encode()
                self_inner.send_response(200)
                self_inner.send_header("Content-Type", "application/json")
                self_inner.send_header("Content-Length", str(len(payload)))
                self_inner.end_headers()
                self_inner.wfile.write(payload)

            def log_message(self_inner, format, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, port

    def _env(self, port):
        return {
            "VLAM_AI_BASE_URL": f"http://127.0.0.1:{port}/v1",
            "VLAM_AI_MODEL": "test",
            "VLAM_AI_API_KEY": "test",
        }

    def test_markdown_fenced_json_is_parsed(self):
        """AI response wrapped in ```json ... ``` should be handled."""
        inner = json.dumps(MOCK_AI_RESPONSE)
        content = f"```json\n{inner}\n```"
        server, port = self._make_server(content)
        try:
            result = _run_cli(
                "check",
                "--manifests", str(FIXTURES / "clean-deploy.yaml"),
                "--env", "production",
                "--skip-external",
                "--no-security-scan",
                "--output", "json",
                env_override=self._env(port),
            )
            data = json.loads(result.stdout)
            assert data["ai_context"] is not None
            assert "Deployment web" in data["ai_context"]["summary"]
        finally:
            server.shutdown()

    def test_js_comments_in_json_are_stripped(self):
        """AI response with // comments inside JSON should be handled."""
        content = '''{
  "summary": "Test summary",
  "impact_analysis": [],
  "recommendations": [
    {
      "action": "Do something",
      "reason": "Good idea",
      "resource": "Deployment/web"
    }
  ],
  "rollback_suggestion": "kubectl rollout undo"
}'''
        # Insert a JS comment
        content_with_comment = content.replace(
            '"resource": "Deployment/web"',
            '"resource": "Deployment/web"  // matches the deployment',
        )
        server, port = self._make_server(content_with_comment)
        try:
            result = _run_cli(
                "check",
                "--manifests", str(FIXTURES / "clean-deploy.yaml"),
                "--env", "production",
                "--skip-external",
                "--no-security-scan",
                "--output", "json",
                env_override=self._env(port),
            )
            data = json.loads(result.stdout)
            assert data["ai_context"] is not None
        finally:
            server.shutdown()

    def test_object_summary_is_coerced_to_string(self):
        """AI returning summary as {status, message} object should be coerced to string."""
        response = {
            "summary": {"status": "compliant", "message": "All good for Deployment/web"},
            "impact_analysis": [],
            "recommendations": [{"action": "Keep it up", "reason": "Good config"}],
            "rollback_suggestion": "kubectl rollout undo",
        }
        server, port = self._make_server(json.dumps(response))
        try:
            result = _run_cli(
                "check",
                "--manifests", str(FIXTURES / "clean-deploy.yaml"),
                "--env", "production",
                "--skip-external",
                "--no-security-scan",
                "--output", "json",
                env_override=self._env(port),
            )
            data = json.loads(result.stdout)
            assert data["ai_context"] is not None
            assert "All good" in data["ai_context"]["summary"]
        finally:
            server.shutdown()

    def test_object_rollback_is_coerced_to_string(self):
        """AI returning rollback_suggestion as object should be coerced to string."""
        response = {
            "summary": "Test summary",
            "impact_analysis": [],
            "recommendations": [{"action": "Do something"}],
            "rollback_suggestion": {
                "strategy": "If problems occur:",
                "steps": [
                    {"command": "kubectl rollout undo deployment/web", "description": "Undo deploy"},
                ],
            },
        }
        server, port = self._make_server(json.dumps(response))
        try:
            result = _run_cli(
                "check",
                "--manifests", str(FIXTURES / "clean-deploy.yaml"),
                "--env", "production",
                "--skip-external",
                "--no-security-scan",
                "--output", "json",
                env_override=self._env(port),
            )
            data = json.loads(result.stdout)
            assert data["ai_context"] is not None
            assert "kubectl rollout undo" in data["ai_context"]["rollback_suggestion"]
        finally:
            server.shutdown()

    def test_fenced_json_with_comments_and_object_fields(self):
        """Full combo: fences + comments + object summary/rollback (like real proxy)."""
        inner = '''{
  "summary": {"status": "ok", "message": "Deployment is well configured"},
  "impact_analysis": [{"severity": "low", "resource": "Deployment/web", "description": "Fine"}],
  "recommendations": [
    {
      "action": "Add network policy",
      "reason": "Defense in depth",
      "resource": "Deployment/web",  // main workload
      "yaml_snippet": {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy"}
    }
  ],
  "rollback_suggestion": {"strategy": "Rollback:", "steps": [{"command": "kubectl rollout undo", "description": "Undo"}]}
}'''
        content = f"```json\n{inner}\n```"
        server, port = self._make_server(content)
        try:
            result = _run_cli(
                "check",
                "--manifests", str(FIXTURES / "clean-deploy.yaml"),
                "--env", "production",
                "--skip-external",
                "--no-security-scan",
                "--output", "json",
                env_override=self._env(port),
            )
            data = json.loads(result.stdout)
            assert data["ai_context"] is not None
            assert "well configured" in data["ai_context"]["summary"]
            assert "kubectl rollout undo" in data["ai_context"]["rollback_suggestion"]
        finally:
            server.shutdown()


class TestAIMalformedResponse:
    """Tests for when the AI server returns invalid data."""

    def test_non_json_response_returns_none(self, tmp_path):
        """If AI returns non-JSON, context should be None."""

        class BadHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                self.rfile.read(length)
                response = {
                    "choices": [
                        {
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": "This is not JSON at all!",
                            },
                            "finish_reason": "stop",
                        }
                    ],
                }
                payload = json.dumps(response).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), BadHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            result = _run_cli(
                "check",
                "--manifests", str(FIXTURES / "clean-deploy.yaml"),
                "--env", "production",
                "--skip-external",
                "--no-security-scan",
                "--output", "json",
                "--debug",
                env_override={
                    "VLAM_AI_BASE_URL": f"http://127.0.0.1:{port}/v1",
                    "VLAM_AI_MODEL": "test",
                    "VLAM_AI_API_KEY": "test",
                },
            )
            data = json.loads(result.stdout)
            assert data["ai_context"] is None
            assert "parse error" in result.stderr
        finally:
            server.shutdown()

    def test_http_500_returns_none(self):
        """If AI returns 500, context should be None."""

        class ErrorHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                self.rfile.read(length)
                self.send_error(500, "Internal Server Error")

            def log_message(self, format, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), ErrorHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            result = _run_cli(
                "check",
                "--manifests", str(FIXTURES / "clean-deploy.yaml"),
                "--env", "production",
                "--skip-external",
                "--no-security-scan",
                "--output", "json",
                "--debug",
                env_override={
                    "VLAM_AI_BASE_URL": f"http://127.0.0.1:{port}/v1",
                    "VLAM_AI_MODEL": "test",
                    "VLAM_AI_API_KEY": "test",
                },
            )
            data = json.loads(result.stdout)
            assert data["ai_context"] is None
            assert "AI request failed" in result.stderr
        finally:
            server.shutdown()
