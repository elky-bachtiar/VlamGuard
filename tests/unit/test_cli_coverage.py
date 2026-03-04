"""Additional coverage tests for vlamguard/cli.py — targeting uncovered lines.

Uncovered before this file:
  102-103  waivers branch in _analyze_manifests
  116      external tools branch (not skip_external)
  124-133  AI context (not skip_ai, security_scan=True)
  141-149  AI context applied to secrets findings
  300-350  compliance command
  354      __main__ guard
"""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from typer.testing import CliRunner

from vlamguard.cli import _analyze_manifests, _load_manifests, _output_response, app
from vlamguard.models.response import AnalyzeResponse, PolicyCheckResult, SecretFinding, SecretsDetectionResult

runner = CliRunner()

_CLEAN_FIXTURE = str(Path(__file__).parent.parent / "fixtures" / "clean-deploy.yaml")
_RISK_FIXTURE = str(Path(__file__).parent.parent / "fixtures" / "evident-risk.yaml")

# ---------------------------------------------------------------------------
# Minimal manifest helpers
# ---------------------------------------------------------------------------

_MINIMAL_MANIFEST = {
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

_MINIMAL_YAML = "kind: Deployment\nmetadata:\n  name: web\n"


def _make_response(blocked: bool = False) -> AnalyzeResponse:
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


# ---------------------------------------------------------------------------
# compliance command
# ---------------------------------------------------------------------------


class TestComplianceCommand:
    def test_compliance_terminal_output(self):
        result = runner.invoke(app, ["compliance"])
        assert result.exit_code == 0
        # Rich table header should appear in output
        assert "checks registered" in result.output

    def test_compliance_json_output(self):
        result = runner.invoke(app, ["compliance", "--output", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) > 0
        # Each entry must have the expected keys
        entry = data[0]
        assert "check_id" in entry
        assert "name" in entry
        assert "severity" in entry
        assert "compliance_tags" in entry

    def test_compliance_json_contains_cis_benchmark(self):
        result = runner.invoke(app, ["compliance", "--output", "json"])
        data = json.loads(result.output)
        # At least one check should have a cis_benchmark value
        cis_entries = [e for e in data if e.get("cis_benchmark")]
        assert len(cis_entries) > 0

    def test_compliance_filter_by_cis(self):
        result = runner.invoke(app, ["compliance", "--framework", "CIS", "--output", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        # All returned checks must have CIS in their compliance_tags
        for entry in data:
            assert any("CIS" in tag for tag in entry["compliance_tags"])

    def test_compliance_filter_by_nsa(self):
        result = runner.invoke(app, ["compliance", "--framework", "NSA", "--output", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        for entry in data:
            assert any("NSA" in tag for tag in entry["compliance_tags"])

    def test_compliance_filter_by_soc2(self):
        result = runner.invoke(app, ["compliance", "--framework", "SOC2", "--output", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        for entry in data:
            assert any("SOC2" in tag for tag in entry["compliance_tags"])

    def test_compliance_filter_case_insensitive(self):
        """--framework flag should accept lowercase and upper-case the value internally."""
        result_lower = runner.invoke(app, ["compliance", "--framework", "cis", "--output", "json"])
        result_upper = runner.invoke(app, ["compliance", "--framework", "CIS", "--output", "json"])
        assert result_lower.exit_code == 0
        assert result_upper.exit_code == 0
        assert json.loads(result_lower.output) == json.loads(result_upper.output)

    def test_compliance_terminal_with_framework_filter(self):
        result = runner.invoke(app, ["compliance", "--framework", "CIS"])
        assert result.exit_code == 0
        assert "checks registered" in result.output

    def test_compliance_unknown_framework_returns_empty_list(self):
        result = runner.invoke(app, ["compliance", "--framework", "UNKNOWN", "--output", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data == []


# ---------------------------------------------------------------------------
# _load_manifests — file-not-found paths
# ---------------------------------------------------------------------------


class TestLoadManifestsErrorPaths:
    def test_manifests_file_not_found_raises_exit(self):
        """Non-existent --manifests path should raise typer.Exit(2)."""
        from typer import Exit

        with pytest.raises(Exit):
            _load_manifests(None, "/nonexistent/manifests.yaml", None)

    def test_values_file_not_found_for_chart_raises_exit(self):
        """Non-existent --values path when using --chart should raise typer.Exit(2)."""
        from typer import Exit

        with pytest.raises(Exit):
            _load_manifests("/some/chart", None, "/nonexistent/values.yaml")

    def test_valid_manifests_path_reads_correctly(self):
        parsed, yaml_content = _load_manifests(None, _CLEAN_FIXTURE, None)
        assert len(parsed) > 0
        assert yaml_content != ""

    def test_valid_values_path_with_chart_is_passed_to_render(self, tmp_path):
        values_file = tmp_path / "values.yaml"
        values_file.write_text("replicas: 2\n")
        manifests = [{"kind": "Deployment", "metadata": {"name": "x"}, "spec": {}}]
        with patch("vlamguard.cli.render_chart", return_value=manifests) as mock_render:
            parsed, _ = _load_manifests("/chart", None, str(values_file))
        mock_render.assert_called_once_with("/chart", {"replicas": 2})
        assert parsed == manifests


# ---------------------------------------------------------------------------
# _analyze_manifests — waivers branch (lines 102-103)
# ---------------------------------------------------------------------------


class TestAnalyzeManifestsWaivers:
    @pytest.mark.asyncio
    async def test_waivers_applied_field_populated(self, tmp_path):
        """When waivers_path is supplied, waivers_applied in response is non-empty."""
        # Build a waiver file that targets 'image_tag' check (present in evident-risk fixture)
        waiver_file = tmp_path / "waivers.yaml"
        waiver_file.write_text(
            "waivers:\n"
            "  - check_id: image_tag\n"
            "    reason: Legacy image pinned for testing\n"
            "    approved_by: security-team@example.com\n"
        )

        # Use a manifest that triggers image_tag failure (latest tag)
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {
                "replicas": 1,
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "app",
                                "image": "nginx:latest",  # triggers image_tag check
                                "securityContext": {"runAsNonRoot": True, "privileged": False},
                            }
                        ]
                    }
                },
            },
        }

        response = await _analyze_manifests(
            [manifest],
            _MINIMAL_YAML,
            "production",
            skip_ai=True,
            skip_external=True,
            security_scan=False,
            waivers_path=str(waiver_file),
        )

        # The image_tag check must have been waived
        waived = [r for r in response.policy_checks if r.check_id == "image_tag" and r.waived]
        assert len(waived) == 1
        assert waived[0].waiver_reason == "Legacy image pinned for testing"
        # Audit trail must be in waivers_applied
        assert any(w["check_id"] == "image_tag" for w in response.waivers_applied)

    @pytest.mark.asyncio
    async def test_no_waivers_path_leaves_waivers_applied_empty(self):
        response = await _analyze_manifests(
            [_MINIMAL_MANIFEST],
            _MINIMAL_YAML,
            "production",
            skip_ai=True,
            skip_external=True,
            security_scan=False,
            waivers_path=None,
        )
        assert response.waivers_applied == []


# ---------------------------------------------------------------------------
# _analyze_manifests — AI paths (lines 124-149)
# ---------------------------------------------------------------------------


class TestAnalyzeManifestsAI:
    @pytest.mark.asyncio
    async def test_ai_security_scan_path_called(self):
        """When skip_ai=False and security_scan=True, get_security_ai_context is called."""
        with patch(
            "vlamguard.cli.get_security_ai_context",
            new_callable=AsyncMock,
            return_value=(None, [], None),
        ) as mock_ai:
            response = await _analyze_manifests(
                [_MINIMAL_MANIFEST],
                _MINIMAL_YAML,
                "production",
                skip_ai=False,
                skip_external=True,
                security_scan=True,
            )
        mock_ai.assert_called_once()
        assert response.risk_score >= 0

    @pytest.mark.asyncio
    async def test_ai_no_security_scan_path_called(self):
        """When skip_ai=False and security_scan=False, get_ai_context is called."""
        with patch(
            "vlamguard.cli.get_ai_context",
            new_callable=AsyncMock,
            return_value=None,
        ) as mock_ai:
            response = await _analyze_manifests(
                [_MINIMAL_MANIFEST],
                _MINIMAL_YAML,
                "production",
                skip_ai=False,
                skip_external=True,
                security_scan=False,
            )
        mock_ai.assert_called_once()
        assert response.security is None

    @pytest.mark.asyncio
    async def test_ai_secrets_data_applied_to_findings(self):
        """When secrets_ai_data is returned, it is applied to SecretFinding objects."""
        secret_finding = SecretFinding(
            severity="critical",
            type="database_credential",
            location="deployment/web -> container/app -> env/DB_PASS",
            pattern="generic_password_env",
            detection="deterministic",
        )
        secrets_result = SecretsDetectionResult(
            total_suspects=1,
            confirmed_secrets=1,
            false_positives=0,
            hard_blocks=[secret_finding],
        )

        # Mock secrets detection to return our prepared result
        with patch("vlamguard.cli.scan_secrets", return_value=secrets_result):
            with patch(
                "vlamguard.cli.get_security_ai_context",
                new_callable=AsyncMock,
                return_value=(
                    None,  # ai_context
                    [],    # hardening_recs
                    {      # secrets_ai_data
                        "summary": "AI summary of findings",
                        "findings": [
                            {
                                "location": "deployment/web -> container/app -> env/DB_PASS",
                                "ai_context": "This exposes the DB password",
                                "recommendation": "Use a Kubernetes Secret instead",
                                "effort": "low",
                            }
                        ],
                    },
                ),
            ):
                response = await _analyze_manifests(
                    [_MINIMAL_MANIFEST],
                    _MINIMAL_YAML,
                    "production",
                    skip_ai=False,
                    skip_external=True,
                    security_scan=True,
                )

        # secrets_result.summary should be set by AI data
        assert response.security is not None
        assert response.security.secrets_detection is not None
        assert response.security.secrets_detection.summary == "AI summary of findings"

        # The SecretFinding should have ai_context applied
        hard_block = response.security.secrets_detection.hard_blocks[0]
        assert hard_block.ai_context == "This exposes the DB password"
        assert hard_block.recommendation == "Use a Kubernetes Secret instead"
        assert hard_block.effort == "low"

    @pytest.mark.asyncio
    async def test_ai_secrets_data_location_mismatch_not_applied(self):
        """When the AI finding location doesn't match any SecretFinding, no update occurs."""
        secret_finding = SecretFinding(
            severity="critical",
            type="database_credential",
            location="deployment/web -> container/app -> env/DB_PASS",
            pattern="generic_password_env",
            detection="deterministic",
        )
        secrets_result = SecretsDetectionResult(
            total_suspects=1,
            confirmed_secrets=1,
            false_positives=0,
            hard_blocks=[secret_finding],
        )

        with patch("vlamguard.cli.scan_secrets", return_value=secrets_result):
            with patch(
                "vlamguard.cli.get_security_ai_context",
                new_callable=AsyncMock,
                return_value=(
                    None,
                    [],
                    {
                        "summary": "AI summary",
                        "findings": [
                            {
                                "location": "completely/different/location",
                                "ai_context": "Should not be applied",
                                "recommendation": "N/A",
                                "effort": "low",
                            }
                        ],
                    },
                ),
            ):
                response = await _analyze_manifests(
                    [_MINIMAL_MANIFEST],
                    _MINIMAL_YAML,
                    "production",
                    skip_ai=False,
                    skip_external=True,
                    security_scan=True,
                )

        hard_block = response.security.secrets_detection.hard_blocks[0]
        assert hard_block.ai_context is None  # Not applied because location didn't match


# ---------------------------------------------------------------------------
# _analyze_manifests — external tools branch (line 116)
# ---------------------------------------------------------------------------


class TestAnalyzeManifestsExternal:
    @pytest.mark.asyncio
    async def test_external_tools_called_when_not_skipped(self):
        """When skip_external=False, run_all_external_tools is invoked."""
        with patch(
            "vlamguard.cli.run_all_external_tools",
            return_value=([], None),
        ) as mock_ext:
            response = await _analyze_manifests(
                [_MINIMAL_MANIFEST],
                _MINIMAL_YAML,
                "production",
                skip_ai=True,
                skip_external=False,
                security_scan=False,
            )
        mock_ext.assert_called_once()
        assert response.external_findings == []

    @pytest.mark.asyncio
    async def test_external_tools_polaris_score_captured(self):
        """polaris_score from external tools is surfaced in the response."""
        with patch(
            "vlamguard.cli.run_all_external_tools",
            return_value=([], 80),
        ):
            response = await _analyze_manifests(
                [_MINIMAL_MANIFEST],
                _MINIMAL_YAML,
                "production",
                skip_ai=True,
                skip_external=False,
                security_scan=False,
            )
        assert response.polaris_score == 80


# ---------------------------------------------------------------------------
# check command — --waivers flag
# ---------------------------------------------------------------------------


class TestCheckCommandWaivers:
    def test_check_with_waivers_file(self, tmp_path):
        waiver_file = tmp_path / "waivers.yaml"
        waiver_file.write_text(
            "waivers:\n"
            "  - check_id: image_tag\n"
            "    reason: Pinned for stability\n"
            "    approved_by: ops@example.com\n"
        )
        result = runner.invoke(
            app,
            [
                "check",
                "--manifests", _RISK_FIXTURE,
                "--env", "production",
                "--skip-ai",
                "--skip-external",
                "--waivers", str(waiver_file),
                "--output", "json",
            ],
        )
        # Exit code is 0 or 1 depending on whether waiver reduces score below threshold
        assert result.exit_code in (0, 1)
        data = json.loads(result.output)
        # The waiver audit trail must appear
        assert "waivers_applied" in data
        assert any(w["check_id"] == "image_tag" for w in data["waivers_applied"])

    def test_check_with_nonexistent_waivers_file(self, tmp_path):
        """A non-existent waivers file is silently ignored by load_waivers (returns [])."""
        result = runner.invoke(
            app,
            [
                "check",
                "--manifests", _CLEAN_FIXTURE,
                "--env", "production",
                "--skip-ai",
                "--skip-external",
                "--waivers", str(tmp_path / "missing.yaml"),
                "--output", "json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["waivers_applied"] == []


# ---------------------------------------------------------------------------
# security-scan command — --waivers flag
# ---------------------------------------------------------------------------


class TestSecurityScanCommandWaivers:
    def test_security_scan_with_waivers_file(self, tmp_path):
        waiver_file = tmp_path / "waivers.yaml"
        waiver_file.write_text(
            "waivers:\n"
            "  - check_id: image_tag\n"
            "    reason: Approved legacy image\n"
            "    approved_by: sec@example.com\n"
        )
        result = runner.invoke(
            app,
            [
                "security-scan",
                "--manifests", _RISK_FIXTURE,
                "--env", "production",
                "--skip-ai",
                "--waivers", str(waiver_file),
                "--output", "json",
            ],
        )
        assert result.exit_code in (0, 1)
        data = json.loads(result.output)
        assert "waivers_applied" in data


# ---------------------------------------------------------------------------
# _output_response — markdown to console (not file)
# ---------------------------------------------------------------------------


class TestOutputResponseMarkdownConsole:
    def test_markdown_output_to_console_calls_console_print(self):
        """When output=markdown and no output_file, console.print is called with the report."""
        response = _make_response()
        with patch("vlamguard.cli.generate_markdown", return_value="# VlamGuard Report\n") as mock_md:
            with patch("vlamguard.cli.console") as mock_console:
                _output_response(response, "markdown", None)
        mock_md.assert_called_once_with(response)
        mock_console.print.assert_called_once_with("# VlamGuard Report\n")


# ---------------------------------------------------------------------------
# __main__ guard (line 354)
# ---------------------------------------------------------------------------


class TestMainGuard:
    def test_main_guard_invokes_app(self):
        """Running the module as __main__ exercises the if __name__ == '__main__' guard.

        We run as a subprocess with `--help` so Click exits cleanly (exit code 0)
        and line 354 (`app()`) is executed without an error.
        """
        import subprocess
        import sys

        result = subprocess.run(
            [sys.executable, "-m", "vlamguard.cli", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        # --help always exits 0 for Typer apps
        assert result.returncode == 0
        assert "vlamguard" in result.stdout.lower()
