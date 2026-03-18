"""GitHub/GitLab integration for automated issue and PR/MR creation."""

import os
import subprocess

_DEFAULT_TIMEOUT = 60


class IntegrationError(Exception):
    """Base error for all integration operations."""


class PlatformError(IntegrationError):
    """Git remote not found, URL unrecognized, or CLI tool missing."""


class IssueCreationError(IntegrationError):
    """Failed to create issue via gh/glab."""


class PRCreationError(IntegrationError):
    """Failed to create PR/MR (dirty tree, push failure, etc.)."""


def get_timeout() -> int:
    """Get subprocess timeout from VLAM_INTEGRATION_TIMEOUT env or default (60s)."""
    try:
        return int(os.environ.get("VLAM_INTEGRATION_TIMEOUT", _DEFAULT_TIMEOUT))
    except (TypeError, ValueError):
        return _DEFAULT_TIMEOUT


def run_cmd(args: list[str]) -> str:
    """Run a subprocess command and return stripped stdout."""
    result = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=get_timeout(),
        check=True,
    )
    return result.stdout.strip()
