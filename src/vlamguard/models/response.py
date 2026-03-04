"""Response models for the VlamGuard API."""

from enum import StrEnum

from pydantic import BaseModel, Field


class RiskLevel(StrEnum):
    """Risk classification levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityGrade(StrEnum):
    """Security grade levels (A=best, F=worst)."""

    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


class PolicyCheckResult(BaseModel):
    """Result of a single policy check."""

    check_id: str
    name: str
    passed: bool
    severity: str = Field(description="critical, high, or medium")
    message: str
    details: dict | None = None
    category: str | None = Field(default=None)
    compliance_tags: list[str] = Field(default_factory=list)
    cis_benchmark: str | None = None
    nsa_control: str | None = None
    waived: bool = False
    waiver_reason: str | None = None


class ImpactItem(BaseModel):
    """Single item in the AI impact analysis."""

    severity: str
    resource: str
    description: str


class Recommendation(BaseModel):
    """A single actionable recommendation with optional file change hint."""

    action: str
    reason: str | None = None  # AI explanation of why this recommendation matters
    resource: str | None = None  # e.g. "Deployment/web"
    yaml_snippet: str | None = None


class AIContext(BaseModel):
    """AI-generated context for the risk report."""

    summary: str = Field(description="2-3 sentences about what changes and why it matters")
    impact_analysis: list[ImpactItem]
    recommendations: list[str | Recommendation]
    rollback_suggestion: str


class SecretFinding(BaseModel):
    """A detected secret or credential in manifests."""

    severity: str = Field(description="critical, high, or medium")
    type: str = Field(description="e.g. private_key, aws_access_key, database_credential")
    location: str = Field(description="e.g. deployment/backend → container/api → env/DATABASE_URL")
    pattern: str = Field(description="Pattern that matched, e.g. private_key_header")
    detection: str = Field(description="deterministic or entropy")
    ai_context: str | None = None
    recommendation: str | None = None
    effort: str | None = None


class SecretsDetectionResult(BaseModel):
    """Aggregated result of secrets scanning."""

    total_suspects: int
    confirmed_secrets: int
    false_positives: int
    hard_blocks: list[SecretFinding] = Field(default_factory=list)
    soft_risks: list[SecretFinding] = Field(default_factory=list)
    summary: str | None = None


class HardeningAction(BaseModel):
    """A single hardening recommendation."""

    priority: int
    category: str = Field(description="container, network, supply_chain, or operational")
    action: str
    effort: str = Field(description="low, medium, or high")
    impact: str = Field(description="low, medium, or high")
    resource: str | None = None  # e.g. "Deployment/web"
    details: str | None = None
    yaml_hint: str | None = None


class SecuritySection(BaseModel):
    """Full security assessment section."""

    secrets_detection: SecretsDetectionResult | None = None
    extended_checks: list[PolicyCheckResult] = Field(default_factory=list)
    hardening_recommendations: list[HardeningAction] = Field(default_factory=list)


class ExternalFinding(BaseModel):
    """Finding from an external validation tool (kube-score, KubeLinter, Polaris)."""

    tool: str = Field(description="Tool name: kube-score, kube-linter, or polaris")
    check_id: str
    severity: str = Field(description="critical, warning, or ok")
    message: str
    resource: str | None = None


class AnalyzeResponse(BaseModel):
    """POST /api/v1/analyze response body."""

    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    blocked: bool
    hard_blocks: list[str]
    policy_checks: list[PolicyCheckResult]
    external_findings: list[ExternalFinding] = Field(default_factory=list)
    polaris_score: int | None = None
    security_grade: SecurityGrade | None = None
    security: SecuritySection | None = None
    ai_context: AIContext | None
    waivers_applied: list[dict] = Field(default_factory=list)
    metadata: dict
