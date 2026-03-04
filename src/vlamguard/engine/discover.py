"""Discover Helm charts in a directory tree."""

from pathlib import Path

_SKIP_DIRS = frozenset({
    ".git", "node_modules", "vendor", "__pycache__",
    ".tox", ".venv", "venv", ".mypy_cache", ".pytest_cache",
})


def discover_charts(root: str | Path) -> list[Path]:
    """Recursively find Helm chart directories under *root*.

    Returns sorted list of chart directory paths (parent of each Chart.yaml),
    relative to *root*. Directories in ``_SKIP_DIRS`` are skipped.
    """
    root_path = Path(root).resolve()
    charts: list[Path] = []
    for chart_yaml in root_path.rglob("Chart.yaml"):
        if any(part in _SKIP_DIRS for part in chart_yaml.parts):
            continue
        charts.append(chart_yaml.parent.relative_to(root_path))
    return sorted(charts)
