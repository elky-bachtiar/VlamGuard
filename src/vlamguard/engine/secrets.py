"""Secrets and credentials detection engine.

Scans Kubernetes manifests for hardcoded secrets using regex patterns
and Shannon entropy analysis. Environment-aware: production = hard block,
dev/staging = soft risk.
"""

import base64
import math
import re

from vlamguard.models.response import SecretFinding, SecretsDetectionResult

HARD_PATTERNS: dict[str, re.Pattern[str]] = {
    "private_key": re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "github_token": re.compile(r"(ghp_|gho_|ghs_|github_pat_)[A-Za-z0-9_]+"),
    "database_url": re.compile(r"(postgresql|mysql|mongodb)://[^:]+:[^@]+@"),
    "generic_password_env": re.compile(r"(?i)(PASSWORD|SECRET|TOKEN|API_KEY)\s*=\s*\S+"),
    "aws_secret_key": re.compile(
        r"(?i)(aws[_-]?secret[_-]?(?:access[_-]?)?key)\s*=\s*[A-Za-z0-9/+=]{40}"
    ),
}

SOFT_PATTERNS: dict[str, re.Pattern[str]] = {
    "suspicious_key_name": re.compile(r"(?i)(api[_-]?key|auth[_-]?token|secret[_-]?key)"),
}

_WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"}
_ENTROPY_THRESHOLD = 4.5
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _scan_hard_patterns(text: str, location: str) -> list[SecretFinding]:
    """Scan text against hard-block regex patterns."""
    findings: list[SecretFinding] = []
    for pattern_name, pattern in HARD_PATTERNS.items():
        if pattern.search(text):
            findings.append(
                SecretFinding(
                    severity="critical",
                    type=pattern_name,
                    location=location,
                    pattern=pattern_name,
                    detection="deterministic",
                )
            )
    return findings


def _scan_soft_patterns(text: str, location: str) -> list[SecretFinding]:
    """Scan text against soft-risk patterns and entropy."""
    findings: list[SecretFinding] = []
    for pattern_name, pattern in SOFT_PATTERNS.items():
        if pattern.search(text):
            findings.append(
                SecretFinding(
                    severity="medium",
                    type=pattern_name,
                    location=location,
                    pattern=pattern_name,
                    detection="deterministic",
                )
            )
    # High-entropy check for values that look like tokens/keys
    if len(text) >= 8 and _shannon_entropy(text) > _ENTROPY_THRESHOLD:
        findings.append(
            SecretFinding(
                severity="high",
                type="high_entropy_string",
                location=location,
                pattern="entropy_check",
                detection="entropy",
            )
        )
    return findings


def _extract_env_vars(manifest: dict) -> list[tuple[str, str, str]]:
    """Extract (key, value, location) tuples from env vars in workload manifests."""
    results: list[tuple[str, str, str]] = []
    kind = manifest.get("kind", "Unknown")
    name = manifest.get("metadata", {}).get("name", "unknown")

    if kind not in _WORKLOAD_KINDS:
        return results

    pod_spec = manifest.get("spec", {}).get("template", {}).get("spec", {})
    all_containers = pod_spec.get("containers", []) + pod_spec.get("initContainers", [])

    for container in all_containers:
        c_name = container.get("name", "unknown")
        for env_var in container.get("env", []):
            var_name = env_var.get("name", "")
            var_value = env_var.get("value")
            if var_value is not None:
                location = f"{kind}/{name} → container/{c_name} → env/{var_name}"
                results.append((var_name, str(var_value), location))

        # Also scan command and args
        for field in ("command", "args"):
            for i, arg in enumerate(container.get(field, [])):
                location = f"{kind}/{name} → container/{c_name} → {field}[{i}]"
                results.append((field, str(arg), location))

    return results


def _extract_configmap_data(manifest: dict) -> list[tuple[str, str, str]]:
    """Extract (key, value, location) tuples from ConfigMap data."""
    results: list[tuple[str, str, str]] = []
    if manifest.get("kind") != "ConfigMap":
        return results

    name = manifest.get("metadata", {}).get("name", "unknown")
    data = manifest.get("data", {})
    for key, value in data.items():
        location = f"ConfigMap/{name} → data/{key}"
        results.append((key, str(value), location))

    return results


def _extract_env_from_refs(
    manifests: list[dict],
) -> list[tuple[str, str, str]]:
    """Extract ConfigMap data referenced via envFrom configMapRef in workloads.

    Cross-references configMapRef names with ConfigMap manifests in the scan
    and produces entries with enhanced location strings.
    """
    # Build a lookup of ConfigMap name → data entries
    configmaps: dict[str, dict[str, str]] = {}
    for manifest in manifests:
        if manifest.get("kind") == "ConfigMap":
            cm_name = manifest.get("metadata", {}).get("name", "unknown")
            cm_data = manifest.get("data", {})
            configmaps[cm_name] = {k: str(v) for k, v in cm_data.items()}

    results: list[tuple[str, str, str]] = []
    for manifest in manifests:
        kind = manifest.get("kind", "Unknown")
        if kind not in _WORKLOAD_KINDS:
            continue

        name = manifest.get("metadata", {}).get("name", "unknown")
        pod_spec = manifest.get("spec", {}).get("template", {}).get("spec", {})
        all_containers = pod_spec.get("containers", []) + pod_spec.get("initContainers", [])

        for container in all_containers:
            c_name = container.get("name", "unknown")
            for env_from in container.get("envFrom", []):
                cm_ref = env_from.get("configMapRef")
                if not cm_ref:
                    continue
                cm_name = cm_ref.get("name", "unknown")
                cm_data = configmaps.get(cm_name, {})
                for data_key, data_value in cm_data.items():
                    location = (
                        f"{kind}/{name} → container/{c_name} → "
                        f"envFrom/configMapRef:{cm_name} → data/{data_key}"
                    )
                    results.append((data_key, data_value, location))

    return results


def _extract_annotations(manifest: dict) -> list[tuple[str, str, str]]:
    """Extract annotations that may contain secrets."""
    results: list[tuple[str, str, str]] = []
    kind = manifest.get("kind", "Unknown")
    name = manifest.get("metadata", {}).get("name", "unknown")
    annotations = manifest.get("metadata", {}).get("annotations", {})
    for key, value in annotations.items():
        location = f"{kind}/{name} → annotation/{key}"
        results.append((key, str(value), location))
    return results


def scan_secrets(
    manifests: list[dict],
    values: dict,
    environment: str,
) -> SecretsDetectionResult:
    """Scan manifests and values for secrets and credentials.

    Args:
        manifests: Parsed Kubernetes manifests.
        values: Helm values dict.
        environment: Target environment (production, staging, dev).

    Returns:
        SecretsDetectionResult with categorized findings.
    """
    is_production = environment == "production"
    hard_blocks: list[SecretFinding] = []
    soft_risks: list[SecretFinding] = []

    # Collect all scannable text from manifests
    all_entries: list[tuple[str, str, str]] = []
    for manifest in manifests:
        all_entries.extend(_extract_env_vars(manifest))
        all_entries.extend(_extract_configmap_data(manifest))
        all_entries.extend(_extract_annotations(manifest))

    # Cross-reference envFrom configMapRef with ConfigMap data
    all_entries.extend(_extract_env_from_refs(manifests))

    # Scan values dict as flat key=value
    _flatten_values(values, "values", all_entries)

    for key, value, location in all_entries:
        # Check combined key=value for hard patterns
        combined = f"{key}={value}"
        hard_findings = _scan_hard_patterns(combined, location)
        if hard_findings:
            if is_production:
                hard_blocks.extend(hard_findings)
            else:
                # In non-prod, confirmed secrets are soft risks
                for f in hard_findings:
                    f.severity = "high"
                soft_risks.extend(hard_findings)
            continue

        # Check key name for suspicious patterns
        key_findings = _scan_soft_patterns(key, location)
        soft_risks.extend(key_findings)

        # Check value for high entropy (skip short values and common patterns)
        if len(value) >= 8:
            entropy = _shannon_entropy(value)
            if entropy > _ENTROPY_THRESHOLD:
                soft_risks.append(
                    SecretFinding(
                        severity="medium",
                        type="high_entropy_string",
                        location=location,
                        pattern="entropy_check",
                        detection="entropy",
                    )
                )

        # Base64 detection for ConfigMap data values
        if "ConfigMap/" in location and _BASE64_RE.match(value):
            try:
                base64.b64decode(value, validate=True)
                soft_risks.append(
                    SecretFinding(
                        severity="medium",
                        type="base64_in_configmap",
                        location=location,
                        pattern="base64_check",
                        detection="deterministic",
                    )
                )
            except Exception:
                pass

    confirmed = len(hard_blocks)
    total = len(hard_blocks) + len(soft_risks)

    return SecretsDetectionResult(
        total_suspects=total,
        confirmed_secrets=confirmed,
        false_positives=0,
        hard_blocks=hard_blocks,
        soft_risks=soft_risks,
    )


def _flatten_values(
    obj: dict | list | str | int | float | bool | None,
    prefix: str,
    out: list[tuple[str, str, str]],
) -> None:
    """Recursively flatten a values dict into (key, value, location) tuples."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            _flatten_values(v, f"{prefix}.{k}", out)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _flatten_values(v, f"{prefix}[{i}]", out)
    elif obj is not None:
        out.append((prefix.rsplit(".", 1)[-1] if "." in prefix else prefix, str(obj), prefix))
