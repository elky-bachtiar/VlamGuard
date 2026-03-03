"""Tests for external tool integrations (kube-score, KubeLinter, Polaris)."""

import json
from unittest.mock import patch, MagicMock

from vlamguard.engine.external import (
    _tool_available,
    run_kube_score,
    run_kube_linter,
    run_polaris,
    run_all_external_tools,
)

SAMPLE_MANIFESTS_YAML = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 3
"""


class TestToolAvailable:
    def test_returns_true_when_found(self):
        with patch("vlamguard.engine.external.shutil.which", return_value="/usr/local/bin/kube-score"):
            assert _tool_available("kube-score") is True

    def test_returns_false_when_not_found(self):
        with patch("vlamguard.engine.external.shutil.which", return_value=None):
            assert _tool_available("kube-score") is False


class TestRunKubeScore:
    def test_returns_empty_when_not_available(self):
        with patch("vlamguard.engine.external._tool_available", return_value=False):
            assert run_kube_score(SAMPLE_MANIFESTS_YAML) == []

    def test_parses_json_output(self):
        kube_score_output = json.dumps([
            {
                "object_name": "web",
                "type_meta": {"apiVersion": "apps/v1", "kind": "Deployment"},
                "checks": [
                    {
                        "check": {"id": "container-image-tag", "name": "Image Tag"},
                        "grade": 1,
                        "comments": [{"summary": "Image uses latest tag"}],
                    },
                    {
                        "check": {"id": "container-resources", "name": "Resource Limits"},
                        "grade": 10,
                        "comments": [],
                    },
                ],
            }
        ])

        mock_result = MagicMock()
        mock_result.stdout = kube_score_output
        mock_result.returncode = 1

        with patch("vlamguard.engine.external._tool_available", return_value=True):
            with patch("vlamguard.engine.external.subprocess.run", return_value=mock_result):
                findings = run_kube_score(SAMPLE_MANIFESTS_YAML)

        assert len(findings) == 1
        assert findings[0].tool == "kube-score"
        assert findings[0].check_id == "container-image-tag"
        assert findings[0].severity == "critical"
        assert findings[0].resource == "Deployment/web"
        assert "latest" in findings[0].message

    def test_skips_ok_grades(self):
        kube_score_output = json.dumps([
            {
                "object_name": "web",
                "type_meta": {"kind": "Deployment"},
                "checks": [
                    {
                        "check": {"id": "good-check", "name": "Good Check"},
                        "grade": 10,
                        "comments": [],
                    },
                ],
            }
        ])

        mock_result = MagicMock()
        mock_result.stdout = kube_score_output

        with patch("vlamguard.engine.external._tool_available", return_value=True):
            with patch("vlamguard.engine.external.subprocess.run", return_value=mock_result):
                findings = run_kube_score(SAMPLE_MANIFESTS_YAML)

        assert len(findings) == 0

    def test_handles_timeout(self):
        import subprocess
        with patch("vlamguard.engine.external._tool_available", return_value=True):
            with patch("vlamguard.engine.external.subprocess.run", side_effect=subprocess.TimeoutExpired("kube-score", 30)):
                assert run_kube_score(SAMPLE_MANIFESTS_YAML) == []

    def test_handles_empty_output(self):
        mock_result = MagicMock()
        mock_result.stdout = ""

        with patch("vlamguard.engine.external._tool_available", return_value=True):
            with patch("vlamguard.engine.external.subprocess.run", return_value=mock_result):
                assert run_kube_score(SAMPLE_MANIFESTS_YAML) == []


class TestRunKubeLinter:
    def test_returns_empty_when_not_available(self):
        with patch("vlamguard.engine.external._tool_available", return_value=False):
            assert run_kube_linter(SAMPLE_MANIFESTS_YAML) == []

    def test_parses_json_output(self):
        kube_linter_output = json.dumps({
            "Checks": [],
            "Diagnostics": [
                {
                    "Message": "container is not set to runAsNonRoot",
                    "Object": {"Kind": "Deployment", "Name": "web", "Namespace": "default"},
                    "Remediation": "Set runAsNonRoot to true",
                    "Check": "no-read-only-root-fs",
                }
            ],
            "Summary": {"ChecksRun": 19, "ObjectsChecked": 1},
        })

        mock_result = MagicMock()
        mock_result.stdout = kube_linter_output
        mock_result.returncode = 1

        with patch("vlamguard.engine.external._tool_available", return_value=True):
            with patch("vlamguard.engine.external.subprocess.run", return_value=mock_result):
                findings = run_kube_linter(SAMPLE_MANIFESTS_YAML)

        assert len(findings) == 1
        assert findings[0].tool == "kube-linter"
        assert findings[0].check_id == "no-read-only-root-fs"
        assert findings[0].severity == "warning"
        assert findings[0].resource == "Deployment/web"

    def test_handles_no_diagnostics(self):
        kube_linter_output = json.dumps({
            "Checks": [],
            "Diagnostics": None,
            "Summary": {"ChecksRun": 19, "ObjectsChecked": 1},
        })

        mock_result = MagicMock()
        mock_result.stdout = kube_linter_output

        with patch("vlamguard.engine.external._tool_available", return_value=True):
            with patch("vlamguard.engine.external.subprocess.run", return_value=mock_result):
                assert run_kube_linter(SAMPLE_MANIFESTS_YAML) == []

    def test_handles_timeout(self):
        import subprocess
        with patch("vlamguard.engine.external._tool_available", return_value=True):
            with patch("vlamguard.engine.external.subprocess.run", side_effect=subprocess.TimeoutExpired("kube-linter", 30)):
                assert run_kube_linter(SAMPLE_MANIFESTS_YAML) == []


class TestRunPolaris:
    def test_returns_none_when_not_available(self):
        with patch("vlamguard.engine.external._tool_available", return_value=False):
            score, findings = run_polaris(SAMPLE_MANIFESTS_YAML)
            assert score is None
            assert findings == []

    def test_parses_json_output_with_score(self):
        polaris_output = json.dumps({
            "AuditTime": "2026-01-01T00:00:00Z",
            "Score": 72.0,
            "Results": [
                {
                    "Name": "web",
                    "Kind": "Deployment",
                    "Namespace": "default",
                    "Results": {
                        "runAsNonRoot": {
                            "ID": "runAsNonRoot",
                            "Message": "Container should set runAsNonRoot",
                            "Severity": "warning",
                            "Category": "Security",
                            "Success": False,
                        },
                        "cpuLimitsMissing": {
                            "ID": "cpuLimitsMissing",
                            "Message": "CPU limits set",
                            "Severity": "warning",
                            "Category": "Efficiency",
                            "Success": True,
                        },
                    },
                }
            ],
        })

        mock_result = MagicMock()
        mock_result.stdout = polaris_output

        with patch("vlamguard.engine.external._tool_available", return_value=True):
            with patch("vlamguard.engine.external.subprocess.run", return_value=mock_result):
                score, findings = run_polaris(SAMPLE_MANIFESTS_YAML)

        assert score == 72
        assert len(findings) == 1
        assert findings[0].tool == "polaris"
        assert findings[0].check_id == "runAsNonRoot"
        assert findings[0].severity == "warning"
        assert findings[0].resource == "Deployment/web"

    def test_maps_danger_severity_to_critical(self):
        polaris_output = json.dumps({
            "Score": 50.0,
            "Results": [
                {
                    "Name": "web",
                    "Kind": "Deployment",
                    "Results": {
                        "privilegeEscalation": {
                            "ID": "privilegeEscalation",
                            "Message": "Privilege escalation allowed",
                            "Severity": "danger",
                            "Success": False,
                        },
                    },
                }
            ],
        })

        mock_result = MagicMock()
        mock_result.stdout = polaris_output

        with patch("vlamguard.engine.external._tool_available", return_value=True):
            with patch("vlamguard.engine.external.subprocess.run", return_value=mock_result):
                score, findings = run_polaris(SAMPLE_MANIFESTS_YAML)

        assert score == 50
        assert findings[0].severity == "critical"

    def test_handles_timeout(self):
        import subprocess
        with patch("vlamguard.engine.external._tool_available", return_value=True):
            with patch("vlamguard.engine.external.subprocess.run", side_effect=subprocess.TimeoutExpired("polaris", 30)):
                score, findings = run_polaris(SAMPLE_MANIFESTS_YAML)
                assert score is None
                assert findings == []


class TestRunAllExternalTools:
    def test_combines_all_findings(self):
        from vlamguard.models.response import ExternalFinding

        ks_findings = [
            ExternalFinding(tool="kube-score", check_id="image-tag", severity="critical", message="Latest tag", resource="Deployment/web")
        ]
        kl_findings = [
            ExternalFinding(tool="kube-linter", check_id="no-root", severity="warning", message="Not non-root", resource="Deployment/web")
        ]
        pol_findings = [
            ExternalFinding(tool="polaris", check_id="runAsNonRoot", severity="warning", message="Should set runAsNonRoot", resource="Deployment/web")
        ]

        with patch("vlamguard.engine.external.run_kube_score", return_value=ks_findings):
            with patch("vlamguard.engine.external.run_kube_linter", return_value=kl_findings):
                with patch("vlamguard.engine.external.run_polaris", return_value=(72, pol_findings)):
                    findings, polaris_score = run_all_external_tools(SAMPLE_MANIFESTS_YAML)

        assert len(findings) == 3
        assert polaris_score == 72
        assert {f.tool for f in findings} == {"kube-score", "kube-linter", "polaris"}

    def test_graceful_when_no_tools(self):
        with patch("vlamguard.engine.external.run_kube_score", return_value=[]):
            with patch("vlamguard.engine.external.run_kube_linter", return_value=[]):
                with patch("vlamguard.engine.external.run_polaris", return_value=(None, [])):
                    findings, polaris_score = run_all_external_tools(SAMPLE_MANIFESTS_YAML)

        assert findings == []
        assert polaris_score is None
