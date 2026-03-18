"""Auto-detect GitHub/GitLab from git remotes."""

import re
import subprocess

from vlamguard.integrations import PlatformError, run_cmd
from vlamguard.models.report import Platform, PlatformInfo

_GITHUB_RE = re.compile(r"github[\.\-]")
_GITLAB_RE = re.compile(r"gitlab[\.\-]")

_PLATFORM_CONFIG: dict[Platform, dict[str, str]] = {
    Platform.GITHUB: {"cli_command": "gh", "body_flag": "--body", "term": "PR"},
    Platform.GITLAB: {"cli_command": "glab", "body_flag": "--description", "term": "MR"},
}


def _detect_platform_from_url(url: str) -> Platform:
    """Detect platform from a git remote URL.

    Matches ``github[.-]`` and ``gitlab[.-]`` substrings to support:
    - HTTPS URLs:  https://github.com/...  https://gitlab.mycompany.com/...
    - Standard SSH: git@github.com:...  git@gitlab.com:...
    - SSH aliases:  git@github-elky-bachtiar:...  git@gitlab-elky-bachtiar:...

    Raises:
        PlatformError: When the URL does not match any supported platform.
    """
    if _GITHUB_RE.search(url):
        return Platform.GITHUB
    if _GITLAB_RE.search(url):
        return Platform.GITLAB
    raise PlatformError(
        f"Could not detect platform from URL: {url}. "
        "Use --platform github or --platform gitlab to specify."
    )


def detect_platform(
    remote: str = "origin",
    platform_override: str | None = None,
) -> PlatformInfo:
    """Detect the hosting platform and validate the CLI tool is available.

    Args:
        remote: Git remote name to inspect (default: ``"origin"``).
        platform_override: Force a specific platform (``"github"`` or ``"gitlab"``).
            When ``None``, the platform is inferred from the remote URL.

    Returns:
        A fully populated :class:`~vlamguard.models.report.PlatformInfo` instance.

    Raises:
        PlatformError: When the remote is not found, the URL is unrecognized,
            the override value is invalid, or the CLI tool is not installed.
    """
    # Fetch remote URL
    try:
        remote_url = run_cmd(["git", "remote", "get-url", remote])
    except subprocess.CalledProcessError:
        raise PlatformError(
            f"Git remote '{remote}' not found. "
            "Use --remote to specify a different remote."
        )

    # Resolve platform
    if platform_override is not None:
        try:
            platform = Platform(platform_override)
        except ValueError:
            raise PlatformError(
                f"Invalid platform: {platform_override}. Use 'github' or 'gitlab'."
            )
    else:
        platform = _detect_platform_from_url(remote_url)

    # Validate CLI tool is present
    config = _PLATFORM_CONFIG[platform]
    cli = config["cli_command"]
    try:
        run_cmd([cli, "--version"])
    except (subprocess.CalledProcessError, FileNotFoundError):
        raise PlatformError(
            f"'{cli}' is not installed or not in PATH. "
            f"Install it to create {config['term']}s on {platform.value}."
        )

    return PlatformInfo(
        platform=platform,
        remote_url=remote_url,
        remote_name=remote,
        cli_command=cli,
        body_flag=config["body_flag"],
        term=config["term"],
    )
