"""Helm chart rendering via subprocess."""

import subprocess
import tempfile
from pathlib import Path

import yaml


class HelmRenderError(Exception):
    """Raised when Helm template rendering fails."""


def parse_manifests(yaml_str: str) -> list[dict]:
    """Parse multi-document YAML string into list of K8s manifest dicts.

    Filters out empty documents and Helm NOTES.txt content.
    """
    manifests: list[dict] = []
    for doc in yaml.safe_load_all(yaml_str):
        if doc is None:
            continue
        if not isinstance(doc, dict):
            continue
        if "kind" not in doc:
            continue
        manifests.append(doc)
    return manifests


def render_chart(chart_path: str, values: dict) -> list[dict]:
    """Render a Helm chart and return parsed K8s manifests.

    Calls 'helm template' subprocess with the given values.
    """
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump(values, f)
            values_file = f.name

        result = subprocess.run(
            [
                "helm",
                "template",
                "vlamguard-check",
                chart_path,
                "--values",
                values_file,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        Path(values_file).unlink(missing_ok=True)

        if result.returncode != 0:
            raise HelmRenderError(
                f"helm template failed (exit {result.returncode}): {result.stderr.strip()}"
            )

        return parse_manifests(result.stdout)

    except FileNotFoundError:
        raise HelmRenderError(
            "helm CLI not found. Install Helm: https://helm.sh/docs/intro/install/"
        )
    except subprocess.TimeoutExpired:
        raise HelmRenderError("helm template timed out after 30 seconds")
