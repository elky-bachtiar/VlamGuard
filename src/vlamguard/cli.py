"""Typer CLI entry point."""

import typer

app = typer.Typer(
    name="vlamguard",
    help="Intelligent change risk engine for infrastructure changes.",
)


@app.command()
def check() -> None:
    """Run risk analysis on a Helm chart."""
    typer.echo("VlamGuard CLI — not yet implemented")
    raise typer.Exit(code=0)


if __name__ == "__main__":
    app()
