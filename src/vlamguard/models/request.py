"""Request models for the VlamGuard API."""

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    """POST /api/v1/analyze request body."""

    chart: str = Field(description="Path to Helm chart or chart reference")
    values: dict = Field(description="Values configuration for Helm rendering")
    environment: str = Field(description="Target environment: dev, staging, production")
    threshold: int | None = Field(
        default=None,
        ge=0,
        le=100,
        description="Custom risk threshold (0-100)",
    )
    skip_ai: bool = Field(
        default=False,
        description="Force analysis without AI context",
    )
