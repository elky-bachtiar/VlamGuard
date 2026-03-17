# tests/e2e/test_report_e2e.py
"""E2E tests for report workflow with real git operations."""

import os
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from vlamguard.integrations import PlatformError, run_cmd
from vlamguard.integrations.platform import detect_platform
from vlamguard.models.report import Platform


@pytest.fixture
def temp_git_repo(tmp_path):
    """Create a temporary git repo with a sample manifest."""
    repo = tmp_path / "test-repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=repo, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, capture_output=True)

    # Add a sample manifest
    manifest = repo / "deploy.yaml"
    manifest.write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n"
        "  replicas: 1\n  template:\n    spec:\n      containers:\n"
        "      - name: app\n        image: nginx:latest\n"
    )
    subprocess.run(["git", "add", "."], cwd=repo, capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, capture_output=True, check=True)

    # Add a remote
    subprocess.run(
        ["git", "remote", "add", "origin", "git@github.com:test/repo.git"],
        cwd=repo, capture_output=True, check=True,
    )

    old_cwd = os.getcwd()
    os.chdir(repo)
    yield repo
    os.chdir(old_cwd)


class TestPlatformDetectionE2E:
    def test_detect_from_real_git_repo(self, temp_git_repo):
        """Detect GitHub from a real git remote."""
        with patch("vlamguard.integrations.platform.run_cmd") as mock:
            # Only mock the CLI version check, let git remote work
            original_run = run_cmd

            def side_effect(args):
                if args[0] == "gh":
                    return "gh version 2.0.0"
                return original_run(args)

            mock.side_effect = side_effect
            info = detect_platform()
            assert info.platform == Platform.GITHUB

    def test_missing_remote_raises(self, temp_git_repo):
        with pytest.raises(PlatformError, match="remote"):
            detect_platform(remote="nonexistent")
