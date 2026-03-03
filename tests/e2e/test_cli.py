"""E2E tests for the VlamGuard CLI."""

import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).parent.parent / "fixtures"
REPO_ROOT = Path(__file__).parent.parent.parent
CHARTS = REPO_ROOT / "charts"
DEMO_CHARTS = REPO_ROOT / "demo" / "charts"


class TestCLIHelp:
    def _run_cli(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "vlamguard.cli", *args],
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_help_shows_usage(self):
        result = self._run_cli("--help")
        assert result.returncode == 0
        assert "check" in result.stdout.lower()

    def test_check_missing_args_fails(self):
        result = self._run_cli("check")
        assert result.returncode == 2


class TestCLIWithFixtures:
    def _run_cli(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "vlamguard.cli", *args],
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_clean_deploy_passes(self):
        result = self._run_cli(
            "check",
            "--manifests", str(FIXTURES / "clean-deploy.yaml"),
            "--env", "production",
            "--skip-ai",
        )
        assert result.returncode == 0

    def test_evident_risk_blocks(self):
        result = self._run_cli(
            "check",
            "--manifests", str(FIXTURES / "evident-risk.yaml"),
            "--env", "production",
            "--skip-ai",
        )
        assert result.returncode == 1

    def test_subtle_impact_warns(self):
        result = self._run_cli(
            "check",
            "--manifests", str(FIXTURES / "subtle-impact.yaml"),
            "--env", "production",
            "--skip-ai",
        )
        assert result.returncode == 0  # score 30, not blocked

    def test_json_output(self):
        result = self._run_cli(
            "check",
            "--manifests", str(FIXTURES / "clean-deploy.yaml"),
            "--env", "production",
            "--skip-ai",
            "--output", "json",
        )
        assert result.returncode == 0
        assert '"risk_score"' in result.stdout

    def test_markdown_output(self):
        result = self._run_cli(
            "check",
            "--manifests", str(FIXTURES / "clean-deploy.yaml"),
            "--env", "production",
            "--skip-ai",
            "--output", "markdown",
        )
        assert result.returncode == 0
        assert "VlamGuard Risk Report" in result.stdout

    def test_hardened_fixture_passes(self):
        result = self._run_cli(
            "check",
            "--manifests", str(FIXTURES / "hardened.yaml"),
            "--env", "production",
            "--skip-ai",
        )
        assert result.returncode == 0

    def test_dev_env_is_lenient(self):
        """In dev, critical checks become soft risks, not hard blocks.

        However, evident-risk.yaml fails many soft-risk checks (image_tag=25,
        security_context=25, readonly_root_fs=20, run_as_user_group=20 = 90),
        which exceeds the 60-point threshold, so it is still blocked.
        """
        result = self._run_cli(
            "check",
            "--manifests", str(FIXTURES / "evident-risk.yaml"),
            "--env", "dev",
            "--skip-ai",
        )
        # In dev, all security checks become soft_risk (not hard_block).
        # But accumulated soft risk (90) > 60 threshold, so still blocked.
        assert result.returncode == 1
        # Verify it's a soft-risk block, not a hard block
        assert "Hard Blocks" not in result.stdout


class TestCLIWithCharts:
    """E2E tests using Helm charts (--chart flag)."""

    def _run_cli(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "vlamguard.cli", *args],
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_vlamguard_own_chart_passes_all_checks(self):
        """VlamGuard's own Helm chart must pass all policy checks (dog-fooding)."""
        result = self._run_cli(
            "check",
            "--chart", str(CHARTS / "vlamguard"),
            "--env", "production",
            "--skip-ai",
        )
        assert result.returncode == 0
        assert "PASSED" in result.stdout

    def test_vlamguard_own_chart_json_has_zero_score(self):
        """VlamGuard's own chart should have risk score 0."""
        result = self._run_cli(
            "check",
            "--chart", str(CHARTS / "vlamguard"),
            "--env", "production",
            "--skip-ai",
            "--output", "json",
        )
        assert result.returncode == 0
        import json
        data = json.loads(result.stdout)
        assert data["risk_score"] == 0
        assert data["blocked"] is False

    def test_demo_hardened_chart_passes(self):
        result = self._run_cli(
            "check",
            "--chart", str(DEMO_CHARTS / "hardened"),
            "--env", "production",
            "--skip-ai",
        )
        assert result.returncode == 0

    def test_demo_best_practices_fail_blocks(self):
        result = self._run_cli(
            "check",
            "--chart", str(DEMO_CHARTS / "best-practices-fail"),
            "--env", "production",
            "--skip-ai",
        )
        assert result.returncode == 1

    def test_demo_evident_risk_chart_blocks(self):
        result = self._run_cli(
            "check",
            "--chart", str(DEMO_CHARTS / "evident-risk"),
            "--env", "production",
            "--skip-ai",
        )
        assert result.returncode == 1

    def test_demo_clean_deploy_chart_blocks_in_production(self):
        """The original clean-deploy demo lacks newer hardening checks
        (readOnlyRootFilesystem, runAsUser/Group) so it blocks in production."""
        result = self._run_cli(
            "check",
            "--chart", str(DEMO_CHARTS / "clean-deploy"),
            "--env", "production",
            "--skip-ai",
        )
        assert result.returncode == 1


class TestSecurityScanCLI:
    """E2E tests for the security-scan command."""

    def _run_cli(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "vlamguard.cli", *args],
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_security_scan_help(self):
        result = self._run_cli("security-scan", "--help")
        assert result.returncode == 0
        assert "security" in result.stdout.lower()

    def test_security_scan_missing_args(self):
        result = self._run_cli("security-scan")
        assert result.returncode == 2

    def test_security_scan_with_fixtures(self):
        result = self._run_cli(
            "security-scan",
            "--manifests", str(FIXTURES / "clean-deploy.yaml"),
            "--env", "production",
            "--skip-ai",
        )
        # clean-deploy has no secrets, so should pass
        assert result.returncode == 0

    def test_security_scan_json_output(self):
        result = self._run_cli(
            "security-scan",
            "--manifests", str(FIXTURES / "clean-deploy.yaml"),
            "--env", "production",
            "--skip-ai",
            "--output", "json",
        )
        assert result.returncode == 0
        import json
        data = json.loads(result.stdout)
        assert "security_grade" in data
        assert "security" in data
        assert data["security"] is not None

    def test_security_scan_with_chart(self):
        result = self._run_cli(
            "security-scan",
            "--chart", str(DEMO_CHARTS / "security-scan-showcase"),
            "--env", "production",
            "--skip-ai",
        )
        # Chart has hardcoded secrets (database_url, generic_password_env) →
        # production secrets cause hard block (score=100, blocked=True)
        assert result.returncode == 1

    def test_security_scan_showcase_json(self):
        result = self._run_cli(
            "security-scan",
            "--chart", str(DEMO_CHARTS / "security-scan-showcase"),
            "--env", "production",
            "--skip-ai",
            "--output", "json",
        )
        import json
        data = json.loads(result.stdout)
        assert data["security_grade"] is not None
        assert data["security"]["secrets_detection"]["confirmed_secrets"] > 0

    def test_check_with_no_security_scan_flag(self):
        result = self._run_cli(
            "check",
            "--manifests", str(FIXTURES / "clean-deploy.yaml"),
            "--env", "production",
            "--skip-ai",
            "--no-security-scan",
            "--output", "json",
        )
        assert result.returncode == 0
        import json
        data = json.loads(result.stdout)
        assert data["security"] is None
        assert data["security_grade"] is None
