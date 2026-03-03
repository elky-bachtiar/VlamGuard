"""E2E tests for the VlamGuard CLI."""

import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).parent.parent / "fixtures"


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
