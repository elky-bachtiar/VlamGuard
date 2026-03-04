"""Additional coverage tests for vlamguard/engine/helm.py — targeting uncovered lines.

Uncovered before this file:
  26   parse_manifests — non-dict document filtered out
  64   render_chart — successful parse path after subprocess call
  67   render_chart — FileNotFoundError → HelmRenderError
  71   render_chart — TimeoutExpired → HelmRenderError
"""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from vlamguard.engine.helm import HelmRenderError, parse_manifests, render_chart


# ---------------------------------------------------------------------------
# parse_manifests — edge-case inputs (line 26)
# ---------------------------------------------------------------------------


class TestParseManifestsEdgeCases:
    def test_empty_string_returns_empty_list(self):
        result = parse_manifests("")
        assert result == []

    def test_only_separators_returns_empty_list(self):
        result = parse_manifests("---\n---\n---\n")
        assert result == []

    def test_none_document_is_filtered(self):
        """YAML with only empty docs (None after parsing) is filtered out."""
        yaml_str = "---\n\n---\n"
        result = parse_manifests(yaml_str)
        assert result == []

    def test_non_dict_document_is_filtered(self):
        """A scalar YAML document (e.g. plain string) must be filtered out (line 26)."""
        yaml_str = "---\nThis is just a string, not a dict.\n"
        result = parse_manifests(yaml_str)
        assert result == []

    def test_list_document_is_filtered(self):
        """A YAML list document must be filtered out as it is not a dict."""
        yaml_str = "---\n- item1\n- item2\n"
        result = parse_manifests(yaml_str)
        assert result == []

    def test_dict_without_kind_is_filtered(self):
        """A dict document missing the 'kind' key must be filtered out."""
        yaml_str = "apiVersion: v1\nmetadata:\n  name: no-kind\n"
        result = parse_manifests(yaml_str)
        assert result == []

    def test_mixed_valid_and_invalid_docs(self):
        """Only documents that are dicts with a 'kind' key should survive."""
        yaml_str = (
            "---\n"
            "This is a string\n"
            "---\n"
            "- list\n"
            "- item\n"
            "---\n"
            "apiVersion: v1\n"
            "kind: ConfigMap\n"
            "metadata:\n"
            "  name: good\n"
            "---\n"
            "apiVersion: v1\n"
            "metadata:\n"
            "  name: no-kind\n"
        )
        result = parse_manifests(yaml_str)
        assert len(result) == 1
        assert result[0]["kind"] == "ConfigMap"

    def test_integer_document_is_filtered(self):
        """An integer YAML document must be filtered out."""
        yaml_str = "---\n42\n"
        result = parse_manifests(yaml_str)
        assert result == []

    def test_valid_document_with_kind_is_kept(self):
        yaml_str = (
            "apiVersion: apps/v1\n"
            "kind: Deployment\n"
            "metadata:\n"
            "  name: web\n"
            "spec:\n"
            "  replicas: 1\n"
        )
        result = parse_manifests(yaml_str)
        assert len(result) == 1
        assert result[0]["kind"] == "Deployment"


# ---------------------------------------------------------------------------
# render_chart — subprocess mocking (lines 64, 67, 71)
# ---------------------------------------------------------------------------


class TestRenderChartSubprocess:
    def _mock_completed_process(self, stdout: str, returncode: int = 0, stderr: str = "") -> MagicMock:
        mock = MagicMock(spec=subprocess.CompletedProcess)
        mock.stdout = stdout
        mock.stderr = stderr
        mock.returncode = returncode
        return mock

    def test_successful_render_returns_parsed_manifests(self):
        """A zero-returncode subprocess call returns the parsed manifests (line 64)."""
        helm_output = (
            "apiVersion: apps/v1\n"
            "kind: Deployment\n"
            "metadata:\n"
            "  name: web\n"
            "spec:\n"
            "  replicas: 2\n"
            "---\n"
            "apiVersion: v1\n"
            "kind: Service\n"
            "metadata:\n"
            "  name: web-svc\n"
        )
        mock_result = self._mock_completed_process(helm_output)

        with patch("subprocess.run", return_value=mock_result):
            manifests = render_chart("/fake/chart", {"replicas": 2})

        assert len(manifests) == 2
        assert manifests[0]["kind"] == "Deployment"
        assert manifests[1]["kind"] == "Service"

    def test_successful_render_with_empty_values(self):
        """render_chart works with an empty values dict."""
        helm_output = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cfg\n"
        mock_result = self._mock_completed_process(helm_output)

        with patch("subprocess.run", return_value=mock_result):
            manifests = render_chart("/fake/chart", {})

        assert len(manifests) == 1
        assert manifests[0]["kind"] == "ConfigMap"

    def test_non_zero_returncode_raises_helm_render_error(self):
        """A non-zero subprocess returncode raises HelmRenderError (line 59-62)."""
        mock_result = self._mock_completed_process(
            stdout="",
            returncode=1,
            stderr="Error: chart not found",
        )

        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(HelmRenderError, match="helm template failed"):
                render_chart("/nonexistent/chart", {})

    def test_non_zero_returncode_message_includes_exit_code_and_stderr(self):
        mock_result = self._mock_completed_process(
            stdout="",
            returncode=2,
            stderr="unable to parse chart: permission denied",
        )

        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(HelmRenderError) as exc_info:
                render_chart("/bad/chart", {})

        assert "exit 2" in str(exc_info.value)
        assert "permission denied" in str(exc_info.value)

    def test_file_not_found_raises_helm_render_error(self):
        """FileNotFoundError (helm CLI missing) wraps into HelmRenderError (line 67)."""
        with patch("subprocess.run", side_effect=FileNotFoundError("helm: command not found")):
            with pytest.raises(HelmRenderError, match="helm CLI not found"):
                render_chart("/fake/chart", {})

    def test_timeout_expired_raises_helm_render_error(self):
        """subprocess.TimeoutExpired wraps into HelmRenderError (line 71)."""
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["helm", "template"], timeout=30),
        ):
            with pytest.raises(HelmRenderError, match="timed out"):
                render_chart("/fake/chart", {})

    def test_successful_render_values_written_to_temp_file(self):
        """Verify that values are passed through to the subprocess call arguments."""
        helm_output = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cfg\n"
        mock_result = self._mock_completed_process(helm_output)

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            render_chart("/my/chart", {"key": "value"})

        call_args = mock_run.call_args[0][0]  # First positional arg: the command list
        assert call_args[0] == "helm"
        assert "template" in call_args
        assert "/my/chart" in call_args
        assert "--values" in call_args

    def test_successful_render_filters_empty_docs(self):
        """parse_manifests is applied to stdout — empty docs are stripped."""
        helm_output = "---\n\n---\nkind: Service\napiVersion: v1\nmetadata:\n  name: svc\n"
        mock_result = self._mock_completed_process(helm_output)

        with patch("subprocess.run", return_value=mock_result):
            manifests = render_chart("/fake/chart", {})

        assert len(manifests) == 1
        assert manifests[0]["kind"] == "Service"
