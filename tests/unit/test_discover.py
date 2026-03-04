"""Tests for vlamguard.engine.discover — chart discovery logic."""

from pathlib import Path

from vlamguard.engine.discover import discover_charts


def _make_chart(base: Path, rel: str) -> None:
    """Create a minimal Chart.yaml at base/rel/Chart.yaml."""
    d = base / rel
    d.mkdir(parents=True, exist_ok=True)
    (d / "Chart.yaml").write_text("name: test\nversion: 0.1.0\n")


class TestDiscoverCharts:
    def test_finds_multiple_charts(self, tmp_path: Path) -> None:
        _make_chart(tmp_path, "charts/app-a")
        _make_chart(tmp_path, "charts/app-b")
        _make_chart(tmp_path, "infra/monitoring")

        result = discover_charts(tmp_path)

        assert len(result) == 3
        assert Path("charts/app-a") in result
        assert Path("charts/app-b") in result
        assert Path("infra/monitoring") in result

    def test_skips_ignored_directories(self, tmp_path: Path) -> None:
        _make_chart(tmp_path, "real-chart")
        _make_chart(tmp_path, ".git/hooks/chart")
        _make_chart(tmp_path, "node_modules/some-pkg")
        _make_chart(tmp_path, "__pycache__/leftover")
        _make_chart(tmp_path, ".venv/lib/chart")

        result = discover_charts(tmp_path)

        assert len(result) == 1
        assert Path("real-chart") in result

    def test_empty_directory(self, tmp_path: Path) -> None:
        result = discover_charts(tmp_path)
        assert result == []

    def test_nested_subchart(self, tmp_path: Path) -> None:
        _make_chart(tmp_path, "parent-chart")
        _make_chart(tmp_path, "parent-chart/charts/subchart")

        result = discover_charts(tmp_path)

        assert len(result) == 2
        assert Path("parent-chart") in result
        assert Path("parent-chart/charts/subchart") in result

    def test_results_are_sorted(self, tmp_path: Path) -> None:
        _make_chart(tmp_path, "z-chart")
        _make_chart(tmp_path, "a-chart")
        _make_chart(tmp_path, "m-chart")

        result = discover_charts(tmp_path)

        assert result == [Path("a-chart"), Path("m-chart"), Path("z-chart")]

    def test_accepts_string_root(self, tmp_path: Path) -> None:
        _make_chart(tmp_path, "my-chart")

        result = discover_charts(str(tmp_path))

        assert result == [Path("my-chart")]

    def test_vendor_directory_skipped(self, tmp_path: Path) -> None:
        _make_chart(tmp_path, "vendor/dep-chart")
        _make_chart(tmp_path, "app")

        result = discover_charts(tmp_path)

        assert result == [Path("app")]
