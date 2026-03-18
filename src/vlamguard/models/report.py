"""Report models for VlamGuard issue/PR creation and fix tracking."""

from enum import StrEnum

from pydantic import BaseModel, Field

from vlamguard.models.response import AnalyzeResponse


class Platform(StrEnum):
    """Supported Git hosting platforms."""

    GITHUB = "github"
    GITLAB = "gitlab"


class PlatformInfo(BaseModel):
    """Platform-specific metadata used to drive issue/PR CLI commands."""

    platform: Platform
    remote_url: str
    remote_name: str = Field(description="Git remote name, e.g. 'origin'")
    cli_command: str = Field(description="CLI tool: 'gh' or 'glab'")
    body_flag: str = Field(description="Body/description flag: '--body' or '--description'")
    term: str = Field(description="PR or MR")


class FixApplied(BaseModel):
    """A single automated fix applied to a manifest file."""

    check_id: str
    file_path: str
    description: str
    before_snippet: str | None = None
    after_snippet: str | None = None


class ReportResponse(BaseModel):
    """Aggregated result of an analysis run including any fixes and platform links."""

    analysis: AnalyzeResponse
    issue_url: str | None = None
    pr_url: str | None = None
    fixes_applied: list[FixApplied] = Field(default_factory=list)
    unfixed: list[str] = Field(default_factory=list)
