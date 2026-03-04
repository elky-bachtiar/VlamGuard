"""Waiver loading, matching, and application logic."""

from datetime import datetime
from pathlib import Path

import yaml

from vlamguard.models.response import PolicyCheckResult
from vlamguard.models.waiver import Waiver


def load_waivers(path: str | Path) -> list[Waiver]:
    """Load waivers from a YAML file.

    Expected format:
    waivers:
      - check_id: image_tag
        reason: "Legacy image requires latest tag"
        approved_by: "security-team@example.com"
        expires: "2026-06-01T00:00:00"
    """
    path = Path(path)
    if not path.exists():
        return []

    with open(path) as f:
        data = yaml.safe_load(f)

    if not data or "waivers" not in data:
        return []

    waivers = []
    for entry in data["waivers"]:
        waivers.append(Waiver(**entry))
    return waivers


def _is_waiver_active(waiver: Waiver) -> bool:
    """Check if a waiver is still active (not expired)."""
    if waiver.expires is None:
        return True
    return datetime.now() < waiver.expires


def _waiver_matches(waiver: Waiver, result: PolicyCheckResult, manifest: dict | None = None) -> bool:
    """Check if a waiver matches a specific policy check result."""
    if waiver.check_id != result.check_id:
        return False

    if not _is_waiver_active(waiver):
        return False

    if manifest is not None:
        if waiver.resource_kind and manifest.get("kind") != waiver.resource_kind:
            return False
        if waiver.resource_name:
            name = manifest.get("metadata", {}).get("name")
            if name != waiver.resource_name:
                return False
        if waiver.namespace:
            ns = manifest.get("metadata", {}).get("namespace")
            if ns != waiver.namespace:
                return False

    return True


def apply_waivers(
    results: list[PolicyCheckResult],
    waivers: list[Waiver],
    manifests: list[dict] | None = None,
) -> tuple[list[PolicyCheckResult], list[dict]]:
    """Apply waivers to policy check results.

    Waivers mark failing checks as waived but do NOT remove them from results.
    The scoring engine treats waived checks as soft_risk instead of hard_block.

    Returns:
        Tuple of (modified results, list of applied waiver info dicts for audit trail)
    """
    if not waivers:
        return results, []

    applied: list[dict] = []

    for i, result in enumerate(results):
        if result.passed:
            continue

        for waiver in waivers:
            # Try matching with manifests if available, else match on check_id only
            matched = False
            if manifests:
                for manifest in manifests:
                    if _waiver_matches(waiver, result, manifest):
                        matched = True
                        break
            else:
                matched = _waiver_matches(waiver, result)

            if matched:
                # Create a new result with waiver applied
                results[i] = PolicyCheckResult(
                    check_id=result.check_id,
                    name=result.name,
                    passed=result.passed,
                    severity=result.severity,
                    message=result.message,
                    details=result.details,
                    category=result.category,
                    compliance_tags=result.compliance_tags,
                    cis_benchmark=result.cis_benchmark,
                    nsa_control=result.nsa_control,
                    waived=True,
                    waiver_reason=waiver.reason,
                )
                applied.append({
                    "check_id": waiver.check_id,
                    "reason": waiver.reason,
                    "approved_by": waiver.approved_by,
                    "expires": waiver.expires.isoformat() if waiver.expires else None,
                })
                break  # Only apply first matching waiver per result

    return results, applied
