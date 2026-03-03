"""Rich colored terminal output for CLI mode."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from vlamguard.models.response import AnalyzeResponse

_LEVEL_COLORS = {
    "low": "green",
    "medium": "yellow",
    "high": "red",
    "critical": "bold red",
}


def print_report(response: AnalyzeResponse, console: Console | None = None) -> None:
    """Print a colored risk report to the terminal."""
    if console is None:
        console = Console()

    color = _LEVEL_COLORS.get(response.risk_level.value, "white")

    status = "[bold red]BLOCKED[/]" if response.blocked else "[bold green]PASSED[/]"
    header = Text.from_markup(
        f"VlamGuard Risk Report — {status}\n"
        f"Risk Score: [{color}]{response.risk_score}/100 ({response.risk_level.value.upper()})[/]\n"
        f"Environment: {response.metadata.get('environment', 'unknown')}"
    )
    console.print(Panel(header, title="VlamGuard", border_style=color))

    if response.hard_blocks:
        console.print("\n[bold red]Hard Blocks:[/]")
        for block in response.hard_blocks:
            console.print(f"  [red]✗[/] {block}")

    table = Table(title="Policy Checks", show_header=True)
    table.add_column("Check", style="bold")
    table.add_column("Result")
    table.add_column("Severity")
    table.add_column("Message")

    for check in response.policy_checks:
        result = "[green]PASS[/]" if check.passed else "[red]FAIL[/]"
        sev_style = {"critical": "red", "high": "yellow", "medium": "cyan"}.get(check.severity, "white")
        table.add_row(check.name, result, f"[{sev_style}]{check.severity}[/]", check.message)

    console.print(table)

    # External tool findings
    if response.external_findings:
        ext_table = Table(title="External Tool Findings", show_header=True)
        ext_table.add_column("Tool", style="bold")
        ext_table.add_column("Check")
        ext_table.add_column("Severity")
        ext_table.add_column("Resource")
        ext_table.add_column("Message")

        for finding in response.external_findings:
            sev_style = {"critical": "red", "warning": "yellow"}.get(finding.severity, "white")
            ext_table.add_row(
                finding.tool,
                finding.check_id,
                f"[{sev_style}]{finding.severity}[/]",
                finding.resource or "-",
                finding.message,
            )

        console.print(ext_table)

    # Polaris score comparison
    if response.polaris_score is not None:
        console.print(
            f"\n[bold]Score Comparison:[/] "
            f"VlamGuard {response.risk_score}/100 (risk) vs "
            f"Polaris {response.polaris_score}/100 (compliance)"
        )

    if response.ai_context:
        console.print(Panel(response.ai_context.summary, title="AI Analysis", border_style="blue"))
        if response.ai_context.recommendations:
            console.print("\n[bold blue]Recommendations:[/]")
            for i, rec in enumerate(response.ai_context.recommendations, 1):
                console.print(f"  {i}. {rec}")
        if response.ai_context.rollback_suggestion:
            console.print(f"\n[dim]Rollback: {response.ai_context.rollback_suggestion}[/]")
    else:
        console.print("\n[dim]AI context not available.[/]")
