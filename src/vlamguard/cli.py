"""Typer CLI entry point — vlamguard check."""

import asyncio
import json as json_module
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

import typer
import yaml
from rich.console import Console

from vlamguard.ai.context import get_ai_context, get_security_ai_context
from vlamguard.ai.filtering import extract_metadata
from vlamguard.engine.external import run_all_external_tools
from vlamguard.engine.grading import calculate_security_grade
from vlamguard.engine.helm import HelmRenderError, parse_manifests, render_chart
from vlamguard.engine.registry import get_check_fns
from vlamguard.engine.scoring import calculate_risk
from vlamguard.engine.secrets import scan_secrets
from vlamguard.models.response import AnalyzeResponse, ExternalFinding, PolicyCheckResult, SecuritySection
from vlamguard.report.generator import generate_markdown
from vlamguard.report.terminal import print_report

import vlamguard.engine.policies  # noqa: F401

app = typer.Typer(
    name="vlamguard",
    help="VlamGuard — Intelligent change risk engine for infrastructure changes.",
)
console = Console()

_EXTENDED_CHECK_IDS = {
    "host_namespace", "dangerous_volume_mounts", "excessive_capabilities",
    "service_account_token", "exposed_services",
}


@app.callback()
def _root() -> None:
    """VlamGuard — Intelligent change risk engine for infrastructure changes."""


def _load_manifests(
    chart: str | None,
    manifests_path: str | None,
    values_path: str | None,
) -> tuple[list[dict], str]:
    """Load and return (parsed_manifests, yaml_content)."""
    if manifests_path:
        manifest_file = Path(manifests_path)
        if not manifest_file.exists():
            console.print(f"[red]Error: manifests file not found: {manifests_path}[/]")
            raise typer.Exit(code=2)
        yaml_content = manifest_file.read_text()
        parsed = parse_manifests(yaml_content)
    else:
        values_data: dict = {}
        if values_path:
            vp = Path(values_path)
            if not vp.exists():
                console.print(f"[red]Error: values file not found: {values_path}[/]")
                raise typer.Exit(code=2)
            values_data = yaml.safe_load(vp.read_text()) or {}
        parsed = render_chart(chart, values_data)
        yaml_content = yaml.dump_all(parsed, default_flow_style=False)

    return parsed, yaml_content


async def _analyze_manifests(
    manifests: list[dict],
    manifests_yaml: str,
    environment: str,
    skip_ai: bool,
    skip_external: bool,
    security_scan: bool = True,
    values: dict | None = None,
) -> AnalyzeResponse:
    """Run analysis on pre-parsed manifests."""
    all_results: list[PolicyCheckResult] = []
    for manifest in manifests:
        for check_fn in get_check_fns():
            result = check_fn(manifest)
            if result.message.endswith("skipped."):
                continue
            all_results.append(result)

    # Secrets detection
    secrets_result = None
    if security_scan:
        secrets_result = scan_secrets(manifests, values or {}, environment)

    risk = calculate_risk(all_results, environment, secrets_result=secrets_result)

    # External tools (optional)
    external_findings: list[ExternalFinding] = []
    polaris_score: int | None = None
    if not skip_external:
        external_findings, polaris_score = run_all_external_tools(manifests_yaml)

    # AI context
    ai_context = None
    hardening_recs = []
    secrets_ai_data = None

    if not skip_ai:
        manifests_metadata = [extract_metadata(m) for m in manifests]
        if security_scan:
            ai_context, hardening_recs, secrets_ai_data = await get_security_ai_context(
                manifests_metadata=manifests_metadata,
                policy_results=all_results,
                secrets_result=secrets_result,
                environment=environment,
            )
        else:
            ai_context = await get_ai_context(
                manifests_metadata=manifests_metadata,
                policy_results=all_results,
                environment=environment,
            )

    # Apply AI context to secrets
    if secrets_result and secrets_ai_data:
        secrets_result.summary = secrets_ai_data.get("summary")
        ai_findings = secrets_ai_data.get("findings", [])
        all_secret_findings = secrets_result.hard_blocks + secrets_result.soft_risks
        for ai_f in ai_findings:
            for sf in all_secret_findings:
                if sf.location == ai_f.get("location"):
                    sf.ai_context = ai_f.get("ai_context")
                    sf.recommendation = ai_f.get("recommendation")
                    sf.effort = ai_f.get("effort")

    # Security grade
    security_grade = None
    security_section = None

    if security_scan:
        extended_checks = [r for r in all_results if r.check_id in _EXTENDED_CHECK_IDS]
        security_grade = calculate_security_grade(
            secrets_result=secrets_result,
            extended_check_results=extended_checks,
            hardening_recommendations=hardening_recs,
            environment=environment,
        )
        security_section = SecuritySection(
            secrets_detection=secrets_result,
            extended_checks=extended_checks,
            hardening_recommendations=hardening_recs,
        )

    return AnalyzeResponse(
        risk_score=risk.score,
        risk_level=risk.level,
        blocked=risk.blocked,
        hard_blocks=risk.hard_blocks,
        policy_checks=all_results,
        external_findings=external_findings,
        polaris_score=polaris_score,
        security_grade=security_grade,
        security=security_section,
        ai_context=ai_context,
        metadata={
            "environment": environment,
            "manifest_count": len(manifests),
        },
    )


def _output_response(
    response: AnalyzeResponse,
    output: str,
    output_file: str | None,
) -> None:
    """Handle output formatting for a response."""
    if output == "json":
        report = response.model_dump_json(indent=2)
        if output_file:
            Path(output_file).write_text(report)
        else:
            print(report)
    elif output == "markdown":
        report = generate_markdown(response)
        if output_file:
            Path(output_file).write_text(report)
        else:
            console.print(report)
    else:
        print_report(response, console)


@app.command()
def check(
    chart: str = typer.Option(None, help="Path to Helm chart directory"),
    values: str = typer.Option(None, help="Path to values YAML file"),
    manifests: str = typer.Option(None, help="Path to pre-rendered YAML manifests (bypasses Helm)"),
    env: str = typer.Option("production", help="Target environment: dev, staging, production"),
    skip_ai: bool = typer.Option(False, "--skip-ai", help="Skip AI context generation"),
    skip_external: bool = typer.Option(False, "--skip-external", help="Skip external tools (kube-score, KubeLinter, Polaris)"),
    no_security_scan: bool = typer.Option(False, "--no-security-scan", help="Disable security scan"),
    output: str = typer.Option("terminal", help="Output format: terminal, json, markdown"),
    output_file: str = typer.Option(None, "--output-file", help="Write report to file"),
) -> None:
    """Run risk analysis on a Helm chart or pre-rendered manifests."""
    if chart is None and manifests is None:
        console.print("[red]Error: provide --chart or --manifests[/]")
        raise typer.Exit(code=2)

    try:
        parsed, yaml_content = _load_manifests(chart, manifests, values)

        # Load values for secrets scanning
        values_data: dict = {}
        if values:
            values_data = yaml.safe_load(Path(values).read_text()) or {}

        response = asyncio.run(
            _analyze_manifests(
                parsed, yaml_content, env, skip_ai, skip_external,
                security_scan=not no_security_scan,
                values=values_data,
            )
        )

        _output_response(response, output, output_file)
        raise typer.Exit(code=1 if response.blocked else 0)

    except HelmRenderError as e:
        console.print(f"[red]Helm Error: {e}[/]")
        raise typer.Exit(code=2)


@app.command("security-scan")
def security_scan(
    chart: str = typer.Option(None, help="Path to Helm chart directory"),
    values: str = typer.Option(None, help="Path to values YAML file"),
    manifests: str = typer.Option(None, help="Path to pre-rendered YAML manifests (bypasses Helm)"),
    env: str = typer.Option("production", help="Target environment: dev, staging, production"),
    skip_ai: bool = typer.Option(False, "--skip-ai", help="Skip AI context generation"),
    output: str = typer.Option("terminal", help="Output format: terminal, json, markdown"),
    output_file: str = typer.Option(None, "--output-file", help="Write report to file"),
) -> None:
    """Run security-focused analysis (secrets + extended checks + grade)."""
    if chart is None and manifests is None:
        console.print("[red]Error: provide --chart or --manifests[/]")
        raise typer.Exit(code=2)

    try:
        parsed, yaml_content = _load_manifests(chart, manifests, values)

        values_data: dict = {}
        if values:
            values_data = yaml.safe_load(Path(values).read_text()) or {}

        response = asyncio.run(
            _analyze_manifests(
                parsed, yaml_content, env, skip_ai,
                skip_external=True,  # security-scan skips external tools
                security_scan=True,
                values=values_data,
            )
        )

        _output_response(response, output, output_file)
        raise typer.Exit(code=1 if response.blocked else 0)

    except HelmRenderError as e:
        console.print(f"[red]Helm Error: {e}[/]")
        raise typer.Exit(code=2)


if __name__ == "__main__":
    app()
