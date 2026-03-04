"""Tests for the Typer CLI (vlamguard check and security-scan commands)."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from vlamguard.cli import app

runner = CliRunner()

# Path to a known-clean fixture
_CLEAN_FIXTURE = str(Path(__file__).parent.parent / "fixtures" / "clean-deploy.yaml")
_RISK_FIXTURE = str(Path(__file__).parent.parent / "fixtures" / "evident-risk.yaml")


# ---------------------------------------------------------------------------
# check command — basic routing
# ---------------------------------------------------------------------------


class TestCheckCommand:
    def test_no_chart_or_manifests_exits_2(self):
        result = runner.invoke(app, ["check", "--skip-ai", "--skip-external"])
        assert result.exit_code == 2

    def test_manifests_file_not_found_exits_2(self):
        result = runner.invoke(
            app,
            ["check", "--manifests", "/nonexistent/path.yaml", "--skip-ai", "--skip-external"],
        )
        assert result.exit_code == 2
        assert "not found" in result.output

    def test_values_file_not_found_with_manifests_raises(self):
        """When --manifests is used, values are loaded post-parse for secrets scanning.
        A nonexistent values file triggers FileNotFoundError (unhandled → exit 1)."""
        result = runner.invoke(
            app,
            [
                "check",
                "--manifests", _CLEAN_FIXTURE,
                "--values", "/nonexistent/values.yaml",
                "--skip-ai",
                "--skip-external",
            ],
        )
        assert result.exit_code == 1  # FileNotFoundError propagates

    def test_clean_manifest_exits_0(self):
        result = runner.invoke(
            app,
            [
                "check",
                "--manifests", _CLEAN_FIXTURE,
                "--env", "production",
                "--skip-ai",
                "--skip-external",
            ],
        )
        assert result.exit_code == 0

    def test_evident_risk_manifest_exits_1(self):
        result = runner.invoke(
            app,
            [
                "check",
                "--manifests", _RISK_FIXTURE,
                "--env", "production",
                "--skip-ai",
                "--skip-external",
            ],
        )
        assert result.exit_code == 1

    def test_json_output_format(self):
        result = runner.invoke(
            app,
            [
                "check",
                "--manifests", _CLEAN_FIXTURE,
                "--env", "production",
                "--skip-ai",
                "--skip-external",
                "--output", "json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "risk_score" in data
        assert "blocked" in data
        assert data["blocked"] is False

    def test_markdown_output_format(self):
        result = runner.invoke(
            app,
            [
                "check",
                "--manifests", _CLEAN_FIXTURE,
                "--env", "production",
                "--skip-ai",
                "--skip-external",
                "--output", "markdown",
            ],
        )
        assert result.exit_code == 0
        assert "VlamGuard" in result.output or "Risk" in result.output

    def test_json_output_to_file(self, tmp_path):
        out_file = str(tmp_path / "report.json")
        result = runner.invoke(
            app,
            [
                "check",
                "--manifests", _CLEAN_FIXTURE,
                "--env", "production",
                "--skip-ai",
                "--skip-external",
                "--output", "json",
                "--output-file", out_file,
            ],
        )
        assert result.exit_code == 0
        data = json.loads(Path(out_file).read_text())
        assert data["blocked"] is False

    def test_markdown_output_to_file(self, tmp_path):
        out_file = str(tmp_path / "report.md")
        result = runner.invoke(
            app,
            [
                "check",
                "--manifests", _CLEAN_FIXTURE,
                "--env", "production",
                "--skip-ai",
                "--skip-external",
                "--output", "markdown",
                "--output-file", out_file,
            ],
        )
        assert result.exit_code == 0
        content = Path(out_file).read_text()
        assert len(content) > 0

    def test_no_security_scan_flag(self):
        result = runner.invoke(
            app,
            [
                "check",
                "--manifests", _CLEAN_FIXTURE,
                "--env", "production",
                "--skip-ai",
                "--skip-external",
                "--no-security-scan",
                "--output", "json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["security"] is None
        assert data["security_grade"] is None

    def test_dev_environment(self):
        result = runner.invoke(
            app,
            [
                "check",
                "--manifests", _RISK_FIXTURE,
                "--env", "dev",
                "--skip-ai",
                "--skip-external",
                "--output", "json",
            ],
        )
        # In dev mode, most checks are off, so likely not blocked
        data = json.loads(result.output)
        assert "risk_score" in data

    def test_generic_exception_from_render_chart_exits_1(self):
        """A generic Exception (not HelmRenderError) propagates as exit 1."""
        with patch("vlamguard.cli.render_chart", side_effect=Exception("Helm not found")):
            result = runner.invoke(
                app,
                [
                    "check",
                    "--chart", "/fake/chart",
                    "--skip-ai",
                    "--skip-external",
                ],
            )
        assert result.exit_code == 1

    def test_chart_with_helm_render_error(self):
        from vlamguard.engine.helm import HelmRenderError

        with patch("vlamguard.cli.render_chart", side_effect=HelmRenderError("chart not found")):
            result = runner.invoke(
                app,
                ["check", "--chart", "/fake/chart", "--skip-ai", "--skip-external"],
            )
        assert result.exit_code == 2
        assert "Helm Error" in result.output

    def test_chart_with_values_file(self, tmp_path):
        values_file = tmp_path / "values.yaml"
        values_file.write_text("replicaCount: 2\n")

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

        with patch("vlamguard.cli.render_chart", return_value=manifests):
            result = runner.invoke(
                app,
                [
                    "check",
                    "--chart", "/fake/chart",
                    "--values", str(values_file),
                    "--skip-ai",
                    "--skip-external",
                    "--output", "json",
                ],
            )
        assert result.exit_code in (0, 1)  # Depends on env severity

    def test_values_file_not_found_for_chart_exits_2(self):
        result = runner.invoke(
            app,
            [
                "check",
                "--chart", "/fake/chart",
                "--values", "/nonexistent/values.yaml",
                "--skip-ai",
                "--skip-external",
            ],
        )
        assert result.exit_code == 2
        assert "not found" in result.output


# ---------------------------------------------------------------------------
# security-scan command
# ---------------------------------------------------------------------------


class TestSecurityScanCommand:
    def test_no_chart_or_manifests_exits_2(self):
        result = runner.invoke(app, ["security-scan", "--skip-ai"])
        assert result.exit_code == 2

    def test_clean_manifest_security_scan(self):
        result = runner.invoke(
            app,
            [
                "security-scan",
                "--manifests", _CLEAN_FIXTURE,
                "--env", "production",
                "--skip-ai",
                "--output", "json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["security"] is not None

    def test_risk_manifest_security_scan(self):
        result = runner.invoke(
            app,
            [
                "security-scan",
                "--manifests", _RISK_FIXTURE,
                "--env", "production",
                "--skip-ai",
                "--output", "json",
            ],
        )
        # May or may not be blocked depending on secrets in fixture
        data = json.loads(result.output)
        assert "security_grade" in data

    def test_security_scan_helm_error_exits_2(self):
        from vlamguard.engine.helm import HelmRenderError

        with patch("vlamguard.cli.render_chart", side_effect=HelmRenderError("bad chart")):
            result = runner.invoke(
                app,
                ["security-scan", "--chart", "/fake/chart", "--skip-ai"],
            )
        assert result.exit_code == 2
        assert "Helm Error" in result.output

    def test_security_scan_terminal_output(self):
        result = runner.invoke(
            app,
            [
                "security-scan",
                "--manifests", _CLEAN_FIXTURE,
                "--env", "production",
                "--skip-ai",
            ],
        )
        assert result.exit_code == 0

    def test_security_scan_markdown_output(self):
        result = runner.invoke(
            app,
            [
                "security-scan",
                "--manifests", _CLEAN_FIXTURE,
                "--env", "production",
                "--skip-ai",
                "--output", "markdown",
            ],
        )
        assert result.exit_code == 0

    def test_security_scan_json_to_file(self, tmp_path):
        out_file = str(tmp_path / "sec-report.json")
        result = runner.invoke(
            app,
            [
                "security-scan",
                "--manifests", _CLEAN_FIXTURE,
                "--env", "production",
                "--skip-ai",
                "--output", "json",
                "--output-file", out_file,
            ],
        )
        assert result.exit_code == 0
        data = json.loads(Path(out_file).read_text())
        assert data["security"] is not None

    def test_security_scan_with_values(self, tmp_path):
        values_file = tmp_path / "values.yaml"
        values_file.write_text("replicaCount: 1\n")

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
                                    "image": "nginx:1.25.3",
                                    "securityContext": {"runAsNonRoot": True, "privileged": False},
                                }
                            ]
                        }
                    },
                },
            }
        ]

        with patch("vlamguard.cli.render_chart", return_value=manifests):
            result = runner.invoke(
                app,
                [
                    "security-scan",
                    "--chart", "/fake/chart",
                    "--values", str(values_file),
                    "--skip-ai",
                    "--output", "json",
                ],
            )
        assert result.exit_code in (0, 1)


# ---------------------------------------------------------------------------
# _load_manifests edge cases
# ---------------------------------------------------------------------------


class TestLoadManifests:
    def test_manifests_path_loads_yaml(self):
        from vlamguard.cli import _load_manifests

        parsed, yaml_content = _load_manifests(None, _CLEAN_FIXTURE, None)
        assert len(parsed) > 0
        assert "kind" in parsed[0]

    def test_chart_path_calls_render_chart(self):
        from vlamguard.cli import _load_manifests

        manifests = [{"kind": "Deployment", "metadata": {"name": "test"}, "spec": {}}]
        with patch("vlamguard.cli.render_chart", return_value=manifests):
            parsed, yaml_content = _load_manifests("/fake/chart", None, None)
        assert len(parsed) == 1

    def test_chart_path_with_values(self, tmp_path):
        from vlamguard.cli import _load_manifests

        values_file = tmp_path / "values.yaml"
        values_file.write_text("replicas: 3\n")

        manifests = [{"kind": "Deployment", "metadata": {"name": "test"}, "spec": {"replicas": 3}}]
        with patch("vlamguard.cli.render_chart", return_value=manifests) as mock_render:
            parsed, yaml_content = _load_manifests("/fake/chart", None, str(values_file))
        mock_render.assert_called_once_with("/fake/chart", {"replicas": 3})


# ---------------------------------------------------------------------------
# _output_response edge cases
# ---------------------------------------------------------------------------


class TestOutputResponse:
    def _make_response(self, blocked=False):
        from vlamguard.models.response import AnalyzeResponse

        return AnalyzeResponse(
            risk_score=0 if not blocked else 100,
            risk_level="low" if not blocked else "critical",
            blocked=blocked,
            hard_blocks=[],
            policy_checks=[],
            external_findings=[],
            polaris_score=None,
            security_grade=None,
            security=None,
            ai_context=None,
            metadata={"environment": "production", "manifest_count": 1},
        )

    def test_terminal_output_calls_print_report(self):
        from vlamguard.cli import _output_response

        response = self._make_response()
        with patch("vlamguard.cli.print_report") as mock_print:
            _output_response(response, "terminal", None)
        mock_print.assert_called_once()

    def test_json_output_prints_json(self, capsys):
        from vlamguard.cli import _output_response

        response = self._make_response()
        _output_response(response, "json", None)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["blocked"] is False

    def test_json_output_to_file(self, tmp_path):
        from vlamguard.cli import _output_response

        response = self._make_response()
        out_file = str(tmp_path / "out.json")
        _output_response(response, "json", out_file)
        data = json.loads(Path(out_file).read_text())
        assert data["blocked"] is False

    def test_markdown_output_to_file(self, tmp_path):
        from vlamguard.cli import _output_response

        response = self._make_response()
        out_file = str(tmp_path / "out.md")
        _output_response(response, "markdown", out_file)
        assert Path(out_file).exists()

    def test_terminal_output_with_file_writes_markdown_and_prints(self, tmp_path):
        """When output=terminal and output_file is set, Rich terminal output is printed
        AND a markdown report is written to the file."""
        from vlamguard.cli import _output_response

        response = self._make_response()
        out_file = str(tmp_path / "dual.md")
        with patch("vlamguard.cli.print_report") as mock_print:
            _output_response(response, "terminal", out_file)
        mock_print.assert_called_once()
        content = Path(out_file).read_text()
        assert "VlamGuard Risk Report" in content
        assert "PASSED" in content

    def test_terminal_output_without_file_no_write(self, tmp_path):
        """When output=terminal and output_file is None, no file is written."""
        from vlamguard.cli import _output_response

        response = self._make_response()
        with patch("vlamguard.cli.print_report"):
            _output_response(response, "terminal", None)
        # No files created in tmp_path
        assert list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------------------
# _analyze_manifests
# ---------------------------------------------------------------------------


class TestAnalyzeManifests:
    @pytest.mark.asyncio
    async def test_skip_ai_and_external(self):
        from vlamguard.cli import _analyze_manifests

        manifests = [
            {
                "kind": "Deployment",
                "metadata": {"name": "web"},
                "spec": {
                    "replicas": 3,
                    "template": {
                        "spec": {
                            "securityContext": {"runAsUser": 1000, "runAsGroup": 1000},
                            "automountServiceAccountToken": False,
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
                                    "livenessProbe": {"httpGet": {"path": "/health", "port": 8080}},
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

        yaml_content = "kind: Deployment\nmetadata:\n  name: web\n"

        response = await _analyze_manifests(
            manifests, yaml_content, "production",
            skip_ai=True, skip_external=True,
            security_scan=True,
        )

        assert response.risk_score >= 0
        assert isinstance(response.blocked, bool)
        assert response.security is not None

    @pytest.mark.asyncio
    async def test_no_security_scan(self):
        from vlamguard.cli import _analyze_manifests

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
                                    "image": "nginx:1.25.3",
                                    "securityContext": {"runAsNonRoot": True, "privileged": False},
                                }
                            ]
                        }
                    },
                },
            }
        ]

        response = await _analyze_manifests(
            manifests, "", "dev",
            skip_ai=True, skip_external=True,
            security_scan=False,
        )

        assert response.security is None
        assert response.security_grade is None
