"""Response models for the VlamGuard API."""

from enum import StrEnum

from pydantic import BaseModel, Field


class RiskLevel(StrEnum):
    """Risk classification levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PolicyCheckResult(BaseModel):
    """Result of a single policy check."""

    check_id: str
    name: str
    passed: bool
    severity: str = Field(description="critical, high, or medium")
    message: str
    details: dict | None = None
    category: str | None = Field(default=None)


class ImpactItem(BaseModel):
    """Single item in the AI impact analysis."""

    severity: str
    resource: str
    description: str


class AIContext(BaseModel):
    """AI-generated context for the risk report."""

    summary: str = Field(description="2-3 sentences about what changes and why it matters")
    impact_analysis: list[ImpactItem]
    recommendations: list[str]
    rollback_suggestion: str


class AnalyzeResponse(BaseModel):
    """POST /api/v1/analyze response body."""

    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    blocked: bool
    hard_blocks: list[str]
    policy_checks: list[PolicyCheckResult]
    ai_context: AIContext | None
    metadata: dict
