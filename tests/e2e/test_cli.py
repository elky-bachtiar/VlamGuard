"""E2E tests for the VlamGuard CLI."""

import json
import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).parent.parent / "fixtures"
REPO_ROOT = Path(__file__).parent.parent.parent
CHARTS = REPO_ROOT / "charts"
DEMO_CHARTS = REPO_ROOT / "demo" / "charts"
WAIVERS_EXAMPLE = REPO_ROOT / "demo" / "waivers-example.yaml"


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
        data = json.loads(result.stdout)
        assert data["security"] is None
        assert data["security_grade"] is None


class TestCLIWithCRDFixtures:
    """E2E tests for CRD ecosystem fixtures (KEDA, Istio, Argo CD, cert-manager, ESO)."""

    def _run_cli(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "vlamguard.cli", *args],
            capture_output=True,
            text=True,
            timeout=30,
        )

    def _run_json(self, fixture: str, env: str = "production") -> dict:
        result = self._run_cli(
            "check",
            "--manifests", str(FIXTURES / fixture),
            "--env", env,
            "--skip-ai",
            "--output", "json",
        )
        return json.loads(result.stdout)

    def test_keda_violations_blocked(self):
        result = self._run_cli(
            "check",
            "--manifests", str(FIXTURES / "crd-keda-violations.yaml"),
            "--env", "production",
            "--skip-ai",
        )
        assert result.returncode == 1

    def test_keda_violations_json_check_ids(self):
        data = self._run_json("crd-keda-violations.yaml")
        fails = {c["check_id"] for c in data["policy_checks"] if not c["passed"]}
        expected = {
            "keda_min_replica_production", "keda_fallback_required",
            "keda_auth_ref_required", "keda_hpa_ownership_validation",
            "keda_max_replica_bound", "keda_trigger_auth_secrets",
            "keda_cooldown_period", "keda_polling_interval",
            "keda_fallback_replica_range", "keda_restore_replicas_warning",
            "keda_inline_secret_detection", "keda_initial_cooldown",
            "keda_job_history_limits", "keda_paused_annotation",
        }
        assert expected.issubset(fails), f"Missing: {expected - fails}"

    def test_istio_violations_blocked(self):
        result = self._run_cli(
            "check",
            "--manifests", str(FIXTURES / "crd-istio-violations.yaml"),
            "--env", "production",
            "--skip-ai",
        )
        assert result.returncode == 1

    def test_istio_violations_json_check_ids(self):
        data = self._run_json("crd-istio-violations.yaml")
        fails = {c["check_id"] for c in data["policy_checks"] if not c["passed"]}
        expected = {
            "istio_virtualservice_timeout", "istio_virtualservice_retries",
            "istio_virtualservice_fault_injection_production",
            "istio_destination_rule_tls", "istio_destination_rule_outlier_detection",
            "istio_destination_rule_connection_pool",
            "istio_peer_auth_strict_mtls", "istio_authz_no_allow_all",
            "istio_gateway_tls_required", "istio_gateway_wildcard_host",
        }
        assert expected.issubset(fails), f"Missing: {expected - fails}"

    def test_argocd_violations_blocked(self):
        result = self._run_cli(
            "check",
            "--manifests", str(FIXTURES / "crd-argocd-violations.yaml"),
            "--env", "production",
            "--skip-ai",
        )
        assert result.returncode == 1

    def test_certmanager_violations_blocked(self):
        result = self._run_cli(
            "check",
            "--manifests", str(FIXTURES / "crd-certmanager-violations.yaml"),
            "--env", "production",
            "--skip-ai",
        )
        assert result.returncode == 1

    def test_eso_violations_blocked(self):
        result = self._run_cli(
            "check",
            "--manifests", str(FIXTURES / "crd-eso-violations.yaml"),
            "--env", "production",
            "--skip-ai",
        )
        assert result.returncode == 1

    def test_core_gaps_violations_blocked(self):
        result = self._run_cli(
            "check",
            "--manifests", str(FIXTURES / "core-gaps-violations.yaml"),
            "--env", "production",
            "--skip-ai",
        )
        assert result.returncode == 1

    def test_core_gaps_json_check_ids(self):
        data = self._run_json("core-gaps-violations.yaml")
        fails = {c["check_id"] for c in data["policy_checks"] if not c["passed"]}
        expected = {
            "host_pid", "host_ipc", "host_namespace",
            "allow_privilege_escalation", "rbac_wildcard_permissions",
            "default_namespace", "pod_security_standards",
            "dangerous_volume_mounts",
        }
        assert expected.issubset(fails), f"Missing: {expected - fails}"

    def test_crd_clean_passes(self):
        result = self._run_cli(
            "check",
            "--manifests", str(FIXTURES / "crd-clean.yaml"),
            "--env", "production",
            "--skip-ai",
        )
        assert result.returncode == 0

    def test_crd_clean_json_zero_score(self):
        data = self._run_json("crd-clean.yaml")
        assert data["risk_score"] == 0
        assert data["blocked"] is False
        fails = [c["check_id"] for c in data["policy_checks"] if not c["passed"]]
        assert fails == [], f"Unexpected failures: {fails}"


class TestCLIWaivers:
    """E2E tests for the waiver workflow."""

    def _run_cli(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "vlamguard.cli", *args],
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_waivers_reduce_hard_blocks(self):
        """Waivers should apply and reduce hard_blocks count."""
        # Without waivers
        baseline = self._run_cli(
            "check",
            "--manifests", str(FIXTURES / "evident-risk.yaml"),
            "--env", "production",
            "--skip-ai",
            "--output", "json",
        )
        baseline_data = json.loads(baseline.stdout)

        # With waivers
        waived = self._run_cli(
            "check",
            "--manifests", str(FIXTURES / "evident-risk.yaml"),
            "--env", "production",
            "--skip-ai",
            "--waivers", str(WAIVERS_EXAMPLE),
            "--output", "json",
        )
        waived_data = json.loads(waived.stdout)

        assert len(waived_data["waivers_applied"]) == 2
        assert len(waived_data["hard_blocks"]) <= len(baseline_data["hard_blocks"])

    def test_nonexistent_waiver_file_no_crash(self):
        """A nonexistent waiver file should not crash — waivers silently return empty."""
        result = self._run_cli(
            "check",
            "--manifests", str(FIXTURES / "clean-deploy.yaml"),
            "--env", "production",
            "--skip-ai",
            "--waivers", "/tmp/nonexistent-waivers.yaml",
        )
        assert result.returncode == 0


class TestCLICompliance:
    """E2E tests for the compliance command."""

    def _run_cli(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "vlamguard.cli", *args],
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_compliance_terminal_output(self):
        result = self._run_cli("compliance")
        assert result.returncode == 0
        assert "checks registered" in result.stdout

    def test_compliance_json_output(self):
        result = self._run_cli("compliance", "--output", "json")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert isinstance(data, list)
        assert len(data) > 50  # At least 50 checks registered
        # All entries have required fields
        for entry in data:
            assert "check_id" in entry
            assert "severity" in entry

    def test_compliance_cis_filter(self):
        result = self._run_cli("compliance", "--framework", "CIS", "--output", "json")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert len(data) > 0
        # All returned checks should have a CIS tag
        for entry in data:
            tags = entry.get("compliance_tags", [])
            assert any("CIS" in tag for tag in tags), (
                f"Check {entry['check_id']} has no CIS tag: {tags}"
            )
