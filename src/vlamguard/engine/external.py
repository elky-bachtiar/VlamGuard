"""External tool integrations — kube-score, KubeLinter, Polaris subprocess wrappers."""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from vlamguard.models.response import ExternalFinding

_KUBE_SCORE_GRADE_MAP = {
    1: "critical",
    5: "warning",
    7: "ok",
    10: "ok",
}


def _tool_available(name: str) -> bool:
    """Check if an external tool binary is on PATH."""
    return shutil.which(name) is not None


def _write_manifests_to_tmpdir(manifests_yaml: str) -> Path:
    """Write rendered manifests to a temp directory for tools that need file paths."""
    tmpdir = Path(tempfile.mkdtemp(prefix="vlamguard-"))
    (tmpdir / "manifests.yaml").write_text(manifests_yaml)
    return tmpdir


def run_kube_score(manifests_yaml: str) -> list[ExternalFinding]:
    """Run kube-score on rendered manifests. Returns empty list if tool unavailable."""
    if not _tool_available("kube-score"):
        return []

    try:
        result = subprocess.run(
            ["kube-score", "score", "-o", "json", "-"],
            input=manifests_yaml,
            capture_output=True,
            text=True,
            timeout=30,
        )
        # kube-score returns exit code 1 when findings exist — that's normal
        if not result.stdout.strip():
            return []

        data = json.loads(result.stdout)
        if not data:
            return []
        findings: list[ExternalFinding] = []

        for obj in data:
            obj_name = obj.get("object_name", "unknown")
            type_meta = obj.get("type_meta", {})
            kind = type_meta.get("kind", "Unknown")

            for check in obj.get("checks", []):
                grade = check.get("grade", 10)
                severity = _KUBE_SCORE_GRADE_MAP.get(grade, "warning")
                if severity == "ok":
                    continue

                check_info = check.get("check", {})
                check_id = check_info.get("id", "unknown")
                check_name = check_info.get("name", check_id)

                comments = check.get("comments", [])
                message = comments[0].get("summary", check_name) if comments else check_name

                findings.append(
                    ExternalFinding(
                        tool="kube-score",
                        check_id=check_id,
                        severity=severity,
                        message=message,
                        resource=f"{kind}/{obj_name}",
                    )
                )

        return findings

    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return []


def run_kube_linter(manifests_yaml: str) -> list[ExternalFinding]:
    """Run KubeLinter on rendered manifests. Returns empty list if tool unavailable."""
    if not _tool_available("kube-linter"):
        return []

    tmpdir = _write_manifests_to_tmpdir(manifests_yaml)
    try:
        result = subprocess.run(
            ["kube-linter", "lint", str(tmpdir), "--format", "json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        # kube-linter returns exit code 1 when findings exist — that's normal
        if not result.stdout.strip():
            return []

        data = json.loads(result.stdout)
        findings: list[ExternalFinding] = []

        for diag in data.get("Diagnostics", []) or []:
            obj = diag.get("Object", {})
            kind = obj.get("Kind", "Unknown")
            name = obj.get("Name", "unknown")

            findings.append(
                ExternalFinding(
                    tool="kube-linter",
                    check_id=diag.get("Check", "unknown"),
                    severity="warning",
                    message=diag.get("Message", ""),
                    resource=f"{kind}/{name}",
                )
            )

        return findings

    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return []
    finally:
        import shutil as _shutil

        _shutil.rmtree(tmpdir, ignore_errors=True)


def run_polaris(manifests_yaml: str) -> tuple[int | None, list[ExternalFinding]]:
    """Run Polaris audit. Returns (score, findings). Score is None if tool unavailable."""
    if not _tool_available("polaris"):
        return None, []

    tmpdir = _write_manifests_to_tmpdir(manifests_yaml)
    try:
        result = subprocess.run(
            ["polaris", "audit", "--audit-path", str(tmpdir), "--format", "json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if not result.stdout.strip():
            return None, []

        data = json.loads(result.stdout)
        score = data.get("Score")
        if isinstance(score, float):
            score = int(score)

        findings: list[ExternalFinding] = []

        for audit_result in data.get("Results", []):
            obj_name = audit_result.get("Name", "unknown")
            kind = audit_result.get("Kind", "Unknown")

            for check_id, check_result in (audit_result.get("Results", {}) or {}).items():
                if check_result.get("Success", True):
                    continue

                severity = check_result.get("Severity", "warning").lower()
                if severity == "danger":
                    severity = "critical"

                findings.append(
                    ExternalFinding(
                        tool="polaris",
                        check_id=check_id,
                        severity=severity,
                        message=check_result.get("Message", ""),
                        resource=f"{kind}/{obj_name}",
                    )
                )

        return score, findings

    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return None, []
    finally:
        import shutil as _shutil

        _shutil.rmtree(tmpdir, ignore_errors=True)


def run_all_external_tools(
    manifests_yaml: str,
) -> tuple[list[ExternalFinding], int | None]:
    """Run all available external tools. Returns (all_findings, polaris_score)."""
    findings: list[ExternalFinding] = []

    findings.extend(run_kube_score(manifests_yaml))
    findings.extend(run_kube_linter(manifests_yaml))

    polaris_score, polaris_findings = run_polaris(manifests_yaml)
    findings.extend(polaris_findings)

    return findings, polaris_score
