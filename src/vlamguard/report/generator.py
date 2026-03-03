"""JSON and Markdown report generation."""

from vlamguard.models.response import AnalyzeResponse


_GRADE_DESCRIPTIONS = {
    "A": "Excellent security posture — all checks pass, hardened configuration.",
    "B": "Good security posture — minor improvements recommended.",
    "C": "Basic security correct, significant hardening gaps.",
    "D": "Serious security issues detected — immediate action required.",
    "F": "Critical security failures — deployment should be blocked.",
}


def generate_markdown(response: AnalyzeResponse) -> str:
    """Generate a Markdown risk report from an AnalyzeResponse."""
    lines: list[str] = []

    status = "BLOCKED" if response.blocked else "PASSED"
    lines.append(f"# VlamGuard Risk Report — {status}")
    lines.append("")
    lines.append(f"**Risk Score:** {response.risk_score}/100 ({response.risk_level.value.upper()})")
    lines.append(f"**Environment:** {response.metadata.get('environment', 'unknown')}")
    lines.append(
        f"**Decision:** {'BLOCKED — pipeline should fail' if response.blocked else 'PASSED — pipeline may proceed'}"
    )
    if response.security_grade:
        lines.append(f"**Security Grade:** {response.security_grade.value}")
    lines.append("")

    if response.hard_blocks:
        lines.append("## Hard Blocks")
        lines.append("")
        for block in response.hard_blocks:
            lines.append(f"- {block}")
        lines.append("")

    lines.append("## Policy Checks")
    lines.append("")
    lines.append("| Check | Result | Severity | Message |")
    lines.append("|-------|--------|----------|---------|")
    for check in response.policy_checks:
        icon = "PASS" if check.passed else "FAIL"
        lines.append(f"| {check.name} | {icon} | {check.severity} | {check.message} |")
    lines.append("")

    # Security Assessment section
    if response.security and response.security_grade:
        lines.append("## Security Assessment")
        lines.append("")
        grade = response.security_grade.value
        desc = _GRADE_DESCRIPTIONS.get(grade, "")
        lines.append(f"**Security Grade: {grade}**")
        lines.append(desc)
        lines.append("")

        # Secrets Detection
        if response.security.secrets_detection:
            sd = response.security.secrets_detection
            lines.append("### Secrets Detection")
            lines.append("")
            if sd.summary:
                lines.append(sd.summary)
                lines.append("")
            if sd.hard_blocks:
                for f in sd.hard_blocks:
                    lines.append(f"- HARD BLOCK — {f.type}: {f.location}")
                    if f.ai_context:
                        lines.append(f"  Context: {f.ai_context}")
                    if f.recommendation:
                        lines.append(f"  Fix: {f.recommendation}")
                lines.append("")
            if sd.soft_risks:
                lines.append(f"{len(sd.soft_risks)} soft risk(s) detected:")
                lines.append("")
                for f in sd.soft_risks:
                    lines.append(f"- {f.severity.upper()} — {f.type}: {f.location} ({f.detection})")
                lines.append("")
            if not sd.hard_blocks and not sd.soft_risks:
                lines.append("No secrets or credentials detected.")
                lines.append("")

        # Extended Security Checks
        if response.security.extended_checks:
            lines.append("### Extended Security Checks")
            lines.append("")
            for check in response.security.extended_checks:
                icon = "PASS" if check.passed else "FAIL"
                lines.append(f"- {icon} {check.name} — {check.message}")
            lines.append("")

        # Hardening Recommendations
        if response.security.hardening_recommendations:
            lines.append("### Hardening Recommendations")
            lines.append("")
            for rec in response.security.hardening_recommendations:
                impact_icon = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW"}.get(rec.impact, rec.impact)
                lines.append(f"{rec.priority}. {impact_icon} — {rec.action} ({rec.effort} effort)")
                if rec.details:
                    lines.append(f"   {rec.details}")
                if rec.yaml_hint:
                    lines.append(f"   ```yaml\n   {rec.yaml_hint}\n   ```")
            lines.append("")

    # External tool findings
    if response.external_findings:
        lines.append("## External Tool Findings")
        lines.append("")
        lines.append("| Tool | Check | Severity | Resource | Message |")
        lines.append("|------|-------|----------|----------|---------|")
        for finding in response.external_findings:
            lines.append(
                f"| {finding.tool} | {finding.check_id} | {finding.severity} | {finding.resource or '-'} | {finding.message} |"
            )
        lines.append("")

    # Polaris score comparison
    if response.polaris_score is not None:
        lines.append("## Score Comparison")
        lines.append("")
        lines.append("| Engine | Score | Scale |")
        lines.append("|--------|-------|-------|")
        lines.append(
            f"| VlamGuard | {response.risk_score}/100 | 0 = no risk, 100 = critical |"
        )
        lines.append(
            f"| Polaris | {response.polaris_score}/100 | 100 = perfect, 0 = all failing |"
        )
        lines.append("")

    if response.ai_context:
        lines.append("## AI Analysis")
        lines.append("")
        lines.append(response.ai_context.summary)
        lines.append("")

        if response.ai_context.impact_analysis:
            lines.append("### Impact Analysis")
            lines.append("")
            for item in response.ai_context.impact_analysis:
                lines.append(
                    f"- **[{item.severity.upper()}]** {item.resource}: {item.description}"
                )
            lines.append("")

        if response.ai_context.recommendations:
            lines.append("### Recommendations")
            lines.append("")
            for i, rec in enumerate(response.ai_context.recommendations, 1):
                lines.append(f"{i}. {rec}")
            lines.append("")

        if response.ai_context.rollback_suggestion:
            lines.append("### Rollback")
            lines.append("")
            lines.append(f"```\n{response.ai_context.rollback_suggestion}\n```")
            lines.append("")
    else:
        lines.append("## AI Analysis")
        lines.append("")
        lines.append("AI context not available.")
        lines.append("")

    lines.append("---")
    lines.append("*Generated by VlamGuard*")
    return "\n".join(lines)
