"""Typer CLI entry point — vlamguard check."""

import asyncio
import json as json_module
from pathlib import Path

import typer
import yaml
from rich.console import Console

from vlamguard.ai.context import get_ai_context
from vlamguard.ai.filtering import extract_metadata
from vlamguard.engine.helm import HelmRenderError, parse_manifests, render_chart
from vlamguard.engine.policies import (
    check_image_tag,
    check_rbac_scope,
    check_replica_count,
    check_resource_limits,
    check_security_context,
)
from vlamguard.engine.scoring import calculate_risk
from vlamguard.models.response import AnalyzeResponse, PolicyCheckResult
from vlamguard.report.generator import generate_markdown
from vlamguard.report.terminal import print_report

app = typer.Typer(
    name="vlamguard",
    help="VlamGuard — Intelligent change risk engine for infrastructure changes.",
)
console = Console()

_ALL_CHECKS = [
    check_image_tag,
    check_security_context,
    check_rbac_scope,
    check_resource_limits,
    check_replica_count,
]


@app.callback()
def _root() -> None:
    """VlamGuard — Intelligent change risk engine for infrastructure changes."""


async def _analyze_manifests(
    manifests: list[dict],
    environment: str,
    skip_ai: bool,
) -> AnalyzeResponse:
    """Run analysis on pre-parsed manifests."""
    all_results: list[PolicyCheckResult] = []
    for manifest in manifests:
        for check_fn in _ALL_CHECKS:
            result = check_fn(manifest)
            if result.message.endswith("skipped."):
                continue
            all_results.append(result)

    risk = calculate_risk(all_results, environment)

    ai_context = None
    if not skip_ai:
        manifests_metadata = [extract_metadata(m) for m in manifests]
        ai_context = await get_ai_context(
            manifests_metadata=manifests_metadata,
            policy_results=all_results,
            environment=environment,
        )

    return AnalyzeResponse(
        risk_score=risk.score,
        risk_level=risk.level,
        blocked=risk.blocked,
        hard_blocks=risk.hard_blocks,
        policy_checks=all_results,
        ai_context=ai_context,
        metadata={
            "environment": environment,
            "manifest_count": len(manifests),
        },
    )


@app.command()
def check(
    chart: str = typer.Option(None, help="Path to Helm chart directory"),
    values: str = typer.Option(None, help="Path to values YAML file"),
    manifests: str = typer.Option(None, help="Path to pre-rendered YAML manifests (bypasses Helm)"),
    env: str = typer.Option("production", help="Target environment: dev, staging, production"),
    skip_ai: bool = typer.Option(False, "--skip-ai", help="Skip AI context generation"),
    output: str = typer.Option("terminal", help="Output format: terminal, json, markdown"),
    output_file: str = typer.Option(None, "--output-file", help="Write report to file"),
) -> None:
    """Run risk analysis on a Helm chart or pre-rendered manifests."""
    if chart is None and manifests is None:
        console.print("[red]Error: provide --chart or --manifests[/]")
        raise typer.Exit(code=2)

    try:
        if manifests:
            manifest_path = Path(manifests)
            if not manifest_path.exists():
                console.print(f"[red]Error: manifests file not found: {manifests}[/]")
                raise typer.Exit(code=2)
            yaml_content = manifest_path.read_text()
            parsed = parse_manifests(yaml_content)
        else:
            values_data: dict = {}
            if values:
                values_path = Path(values)
                if not values_path.exists():
                    console.print(f"[red]Error: values file not found: {values}[/]")
                    raise typer.Exit(code=2)
                values_data = yaml.safe_load(values_path.read_text()) or {}
            parsed = render_chart(chart, values_data)

        response = asyncio.run(_analyze_manifests(parsed, env, skip_ai))

        if output == "json":
            report = response.model_dump_json(indent=2)
            if output_file:
                Path(output_file).write_text(report)
            else:
                console.print(report)
        elif output == "markdown":
            report = generate_markdown(response)
            if output_file:
                Path(output_file).write_text(report)
            else:
                console.print(report)
        else:
            print_report(response, console)

        raise typer.Exit(code=1 if response.blocked else 0)

    except HelmRenderError as e:
        console.print(f"[red]Helm Error: {e}[/]")
        raise typer.Exit(code=2)


if __name__ == "__main__":
    app()
