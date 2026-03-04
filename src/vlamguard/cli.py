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
from vlamguard.engine.discover import discover_charts
from vlamguard.engine.registry import get_all_checks, get_check_fns, get_compliance_info
from vlamguard.engine.scoring import calculate_risk
from vlamguard.engine.secrets import scan_secrets
from vlamguard.engine.waivers import apply_waivers, load_waivers
from vlamguard.models.response import AnalyzeResponse, ExternalFinding, PolicyCheckResult, SecuritySection
from vlamguard.report.generator import generate_markdown
from vlamguard.report.terminal import print_report

import vlamguard.engine.policies  # noqa: F401
import vlamguard.engine.policies_extended  # noqa: F401
import vlamguard.engine.crd.keda  # noqa: F401
import vlamguard.engine.crd.argocd  # noqa: F401
import vlamguard.engine.crd.istio  # noqa: F401
import vlamguard.engine.crd.certmanager  # noqa: F401
import vlamguard.engine.crd.externalsecrets  # noqa: F401

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
    waivers_path: str | None = None,
) -> AnalyzeResponse:
    """Run analysis on pre-parsed manifests."""
    all_results: list[PolicyCheckResult] = []
    for manifest in manifests:
        for check_fn in get_check_fns():
            result = check_fn(manifest)
            if result.message.endswith("skipped."):
                continue
            all_results.append(result)

    # Apply waivers if provided
    waivers_applied: list[dict] = []
    if waivers_path:
        waivers = load_waivers(waivers_path)
        all_results, waivers_applied = apply_waivers(all_results, waivers, manifests)

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
        waivers_applied=waivers_applied,
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
    """Handle output formatting for a response.

    When output is "terminal" and output_file is set, the Rich report is
    printed to the terminal AND a Markdown report is written to the file,
    giving both human-friendly console output and a persistent report.
    """
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
        if output_file:
            Path(output_file).write_text(generate_markdown(response))


@app.command()
def check(
    chart: str = typer.Option(None, help="Path to Helm chart directory"),
    values: str = typer.Option(None, help="Path to values YAML file"),
    manifests: str = typer.Option(None, help="Path to pre-rendered YAML manifests (bypasses Helm)"),
    env: str = typer.Option("production", help="Target environment: dev, staging, production"),
    skip_ai: bool = typer.Option(False, "--skip-ai", help="Skip AI context generation"),
    skip_external: bool = typer.Option(False, "--skip-external", help="Skip external tools (kube-score, KubeLinter, Polaris)"),
    no_security_scan: bool = typer.Option(False, "--no-security-scan", help="Disable security scan"),
    waivers: str = typer.Option(None, "--waivers", help="Path to waivers YAML file"),
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
                waivers_path=waivers,
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
    waivers: str = typer.Option(None, "--waivers", help="Path to waivers YAML file"),
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
                waivers_path=waivers,
            )
        )

        _output_response(response, output, output_file)
        raise typer.Exit(code=1 if response.blocked else 0)

    except HelmRenderError as e:
        console.print(f"[red]Helm Error: {e}[/]")
        raise typer.Exit(code=2)


@app.command("compliance")
def compliance(
    framework: str = typer.Option(None, help="Filter by framework: CIS, NSA, SOC2"),
    output: str = typer.Option("terminal", help="Output format: terminal, json"),
) -> None:
    """List all policy checks with their compliance mappings."""
    checks = get_all_checks()
    compliance_info = get_compliance_info()

    if framework:
        framework_upper = framework.upper()
        checks = [
            c for c in checks
            if any(framework_upper in tag for tag in c.compliance_tags)
        ]

    if output == "json":
        data = []
        for c in checks:
            info = compliance_info.get(c.check_id, {})
            data.append({
                "check_id": c.check_id,
                "name": c.name,
                "severity": c.severity,
                "category": c.category,
                "compliance_tags": info.get("compliance_tags", []),
                "cis_benchmark": info.get("cis_benchmark"),
                "nsa_control": info.get("nsa_control"),
                "description": info.get("description"),
                "remediation": info.get("remediation"),
            })
        print(json_module.dumps(data, indent=2))
    else:
        from rich.table import Table

        table = Table(title="VlamGuard Compliance Map")
        table.add_column("Check ID", style="cyan")
        table.add_column("Name")
        table.add_column("Severity", style="bold")
        table.add_column("CIS", style="green")
        table.add_column("NSA", style="blue")
        table.add_column("Tags", style="dim")

        for c in checks:
            info = compliance_info.get(c.check_id, {})
            tags = ", ".join(info.get("compliance_tags", []))
            table.add_row(
                c.check_id,
                c.name,
                c.severity,
                info.get("cis_benchmark") or "-",
                info.get("nsa_control") or "-",
                tags or "-",
            )

        console.print(table)
        console.print(f"\n[bold]{len(checks)}[/] checks registered.")


@app.command()
def discover(
    root: str = typer.Argument(".", help="Root directory to scan for Helm charts"),
    env: str = typer.Option("production", help="Target environment: dev, staging, production"),
    skip_ai: bool = typer.Option(False, "--skip-ai", help="Skip AI context generation"),
    skip_external: bool = typer.Option(False, "--skip-external", help="Skip external tools"),
    no_security_scan: bool = typer.Option(False, "--no-security-scan", help="Disable security scan"),
    waivers: str = typer.Option(None, "--waivers", help="Path to waivers YAML file"),
    output: str = typer.Option("terminal", help="Output format: terminal, json, markdown"),
    output_file: str = typer.Option(None, "--output-file", help="Write report to file"),
) -> None:
    """Discover and analyse all Helm charts under a directory tree."""
    from rich.table import Table

    root_path = Path(root).resolve()
    charts = discover_charts(root_path)

    if not charts:
        console.print("[yellow]No Helm charts found.[/]")
        raise typer.Exit(code=0)

    console.print(f"[bold]Discovered {len(charts)} chart(s):[/]")
    for c in charts:
        console.print(f"  • {c}")
    console.print()

    results: list[dict] = []
    any_blocked = False

    for chart_rel in charts:
        chart_abs = str(root_path / chart_rel)
        console.print(f"[bold cyan]── Analysing {chart_rel} ──[/]")

        try:
            parsed, yaml_content = _load_manifests(chart_abs, None, None)
            response = asyncio.run(
                _analyze_manifests(
                    parsed, yaml_content, env, skip_ai, skip_external,
                    security_scan=not no_security_scan,
                    waivers_path=waivers,
                )
            )

            if output != "json":
                _output_response(response, output, None)

            if response.blocked:
                any_blocked = True

            results.append({
                "chart": str(chart_rel),
                "risk_score": response.risk_score,
                "risk_level": response.risk_level,
                "grade": response.security_grade,
                "blocked": response.blocked,
                "status": "BLOCK" if response.blocked else "PASS",
            })

        except HelmRenderError as e:
            console.print(f"[red]  Helm Error: {e}[/]")
            results.append({
                "chart": str(chart_rel),
                "risk_score": None,
                "risk_level": None,
                "grade": None,
                "blocked": False,
                "status": "ERROR",
            })

        console.print()

    # JSON output — wrap everything
    if output == "json":
        passed = sum(1 for r in results if r["status"] == "PASS")
        blocked = sum(1 for r in results if r["status"] == "BLOCK")
        errors = sum(1 for r in results if r["status"] == "ERROR")
        payload = {
            "charts": results,
            "summary": {
                "total": len(results),
                "passed": passed,
                "blocked": blocked,
                "errors": errors,
            },
        }
        report = json_module.dumps(payload, indent=2)
        if output_file:
            Path(output_file).write_text(report)
        else:
            print(report)
    else:
        # Summary table
        table = Table(title="Discovery Summary")
        table.add_column("Chart", style="cyan")
        table.add_column("Score", justify="right")
        table.add_column("Grade")
        table.add_column("Status")

        for r in results:
            score_str = str(r["risk_score"]) if r["risk_score"] is not None else "-"
            grade_str = r["grade"] or "-"
            status = r["status"]
            style = {"PASS": "green", "BLOCK": "red", "ERROR": "yellow"}.get(status, "")
            table.add_row(r["chart"], score_str, grade_str, f"[{style}]{status}[/]")

        console.print(table)

        if output_file:
            Path(output_file).write_text(generate_markdown_summary(results))

    raise typer.Exit(code=1 if any_blocked else 0)


def generate_markdown_summary(results: list[dict]) -> str:
    """Generate a markdown summary table for discovered charts."""
    lines = ["# VlamGuard Discovery Report", "", "| Chart | Score | Grade | Status |", "|-------|-------|-------|--------|"]
    for r in results:
        score = str(r["risk_score"]) if r["risk_score"] is not None else "-"
        grade = r["grade"] or "-"
        lines.append(f"| {r['chart']} | {score} | {grade} | {r['status']} |")
    passed = sum(1 for r in results if r["status"] == "PASS")
    blocked = sum(1 for r in results if r["status"] == "BLOCK")
    errors = sum(1 for r in results if r["status"] == "ERROR")
    lines.extend(["", f"**Total:** {len(results)} | **Passed:** {passed} | **Blocked:** {blocked} | **Errors:** {errors}"])
    return "\n".join(lines)


if __name__ == "__main__":
    app()
