"""Tests for the ``vlamguard discover`` CLI command."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from vlamguard.cli import app
from vlamguard.engine.helm import HelmRenderError
from vlamguard.models.response import AnalyzeResponse

runner = CliRunner()


def _fake_response(*, blocked: bool = False, score: int = 15, grade: str = "B") -> AnalyzeResponse:
    return AnalyzeResponse(
        risk_score=score,
        risk_level="low",
        blocked=blocked,
        hard_blocks=[],
        policy_checks=[],
        external_findings=[],
        polaris_score=None,
        security_grade=grade,
        security=None,
        ai_context=None,
        waivers_applied=[],
        metadata={"environment": "production", "manifest_count": 1},
    )


class TestDiscoverNoCharts:
    def test_no_charts_found(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["discover", str(tmp_path)])
        assert result.exit_code == 0
        assert "No Helm charts found" in result.output


class TestDiscoverWithCharts:
    @patch("vlamguard.cli._analyze_manifests", new_callable=AsyncMock)
    @patch("vlamguard.cli._load_manifests")
    @patch("vlamguard.cli.discover_charts")
    def test_discovers_and_analyses(self, mock_discover, mock_load, mock_analyze) -> None:
        mock_discover.return_value = [Path("charts/app-a"), Path("charts/app-b")]
        mock_load.return_value = ([{"kind": "Deployment", "metadata": {"name": "x"}}], "kind: Deployment\n")
        mock_analyze.return_value = _fake_response()

        result = runner.invoke(app, ["discover", "/some/root"])

        assert "Discovered 2 chart(s)" in result.output
        assert "charts/app-a" in result.output
        assert "charts/app-b" in result.output
        assert "Discovery Summary" in result.output
        assert result.exit_code == 0

    @patch("vlamguard.cli._analyze_manifests", new_callable=AsyncMock)
    @patch("vlamguard.cli._load_manifests")
    @patch("vlamguard.cli.discover_charts")
    def test_exit_code_1_when_blocked(self, mock_discover, mock_load, mock_analyze) -> None:
        mock_discover.return_value = [Path("charts/app")]
        mock_load.return_value = ([{}], "")
        mock_analyze.return_value = _fake_response(blocked=True)

        result = runner.invoke(app, ["discover", "/root"])

        assert result.exit_code == 1

    @patch("vlamguard.cli._analyze_manifests", new_callable=AsyncMock)
    @patch("vlamguard.cli._load_manifests")
    @patch("vlamguard.cli.discover_charts")
    def test_json_output(self, mock_discover, mock_load, mock_analyze) -> None:
        mock_discover.return_value = [Path("my-chart")]
        mock_load.return_value = ([{}], "")
        mock_analyze.return_value = _fake_response(score=20, grade="A")

        result = runner.invoke(app, ["discover", "/root", "--output", "json"])

        # Extract JSON object from mixed output
        lines = result.output.strip().split("\n")
        json_start = next(i for i, l in enumerate(lines) if l.strip().startswith("{"))
        data = json.loads("\n".join(lines[json_start:]))
        assert "charts" in data
        assert "summary" in data
        assert data["summary"]["total"] == 1
        assert data["summary"]["passed"] == 1
        assert data["charts"][0]["chart"] == "my-chart"
        assert data["charts"][0]["risk_score"] == 20

    @patch("vlamguard.cli._load_manifests", side_effect=HelmRenderError("bad chart"))
    @patch("vlamguard.cli.discover_charts")
    def test_helm_error_continues(self, mock_discover, mock_load) -> None:
        mock_discover.return_value = [Path("bad-chart"), Path("good-chart")]
        # First call raises, second needs a different setup:
        # We need to make _load_manifests raise for first, succeed for second
        pass

    @patch("vlamguard.cli._analyze_manifests", new_callable=AsyncMock)
    @patch("vlamguard.cli._load_manifests")
    @patch("vlamguard.cli.discover_charts")
    def test_error_handling_per_chart(self, mock_discover, mock_load, mock_analyze) -> None:
        mock_discover.return_value = [Path("chart-a"), Path("chart-b")]

        # First chart errors, second succeeds
        mock_load.side_effect = [
            HelmRenderError("render failed"),
            ([{"kind": "Deployment", "metadata": {"name": "x"}}], "kind: Deployment\n"),
        ]
        mock_analyze.return_value = _fake_response()

        result = runner.invoke(app, ["discover", "/root"])

        assert "Helm Error" in result.output
        assert "Discovery Summary" in result.output
        assert "ERROR" in result.output
        assert "PASS" in result.output
        assert result.exit_code == 0

    @patch("vlamguard.cli._analyze_manifests", new_callable=AsyncMock)
    @patch("vlamguard.cli._load_manifests")
    @patch("vlamguard.cli.discover_charts")
    def test_summary_table_columns(self, mock_discover, mock_load, mock_analyze) -> None:
        mock_discover.return_value = [Path("app")]
        mock_load.return_value = ([{}], "")
        mock_analyze.return_value = _fake_response(score=42, grade="C")

        result = runner.invoke(app, ["discover", "/root"])

        assert "42" in result.output
        assert "PASS" in result.output

    @patch("vlamguard.cli._analyze_manifests", new_callable=AsyncMock)
    @patch("vlamguard.cli._load_manifests")
    @patch("vlamguard.cli.discover_charts")
    def test_json_output_with_error(self, mock_discover, mock_load, mock_analyze) -> None:
        mock_discover.return_value = [Path("chart-ok"), Path("chart-bad")]
        mock_load.side_effect = [
            ([{}], ""),
            HelmRenderError("fail"),
        ]
        mock_analyze.return_value = _fake_response()

        result = runner.invoke(app, ["discover", "/root", "--output", "json"])

        # Parse JSON from output (skip the discovery header lines)
        lines = result.output.strip().split("\n")
        json_start = next(i for i, l in enumerate(lines) if l.strip().startswith("{"))
        data = json.loads("\n".join(lines[json_start:]))

        assert data["summary"]["errors"] == 1
        assert data["summary"]["passed"] == 1

    @patch("vlamguard.cli._analyze_manifests", new_callable=AsyncMock)
    @patch("vlamguard.cli._load_manifests")
    @patch("vlamguard.cli.discover_charts")
    def test_json_output_to_file(self, mock_discover, mock_load, mock_analyze, tmp_path: Path) -> None:
        mock_discover.return_value = [Path("app")]
        mock_load.return_value = ([{}], "")
        mock_analyze.return_value = _fake_response()

        out_file = str(tmp_path / "report.json")
        result = runner.invoke(app, ["discover", "/root", "--output", "json", "--output-file", out_file])

        assert Path(out_file).exists()
        data = json.loads(Path(out_file).read_text())
        assert data["summary"]["total"] == 1


class TestDiscoverMarkdownOutput:
    @patch("vlamguard.cli._analyze_manifests", new_callable=AsyncMock)
    @patch("vlamguard.cli._load_manifests")
    @patch("vlamguard.cli.discover_charts")
    def test_markdown_output_to_file(self, mock_discover, mock_load, mock_analyze, tmp_path: Path) -> None:
        mock_discover.return_value = [Path("app")]
        mock_load.return_value = ([{}], "")
        mock_analyze.return_value = _fake_response(score=10, grade="A")

        out_file = str(tmp_path / "report.md")
        result = runner.invoke(app, ["discover", "/root", "--output", "markdown", "--output-file", out_file])

        content = Path(out_file).read_text()
        assert "VlamGuard Discovery Report" in content
        assert "app" in content
