"""FastAPI application entry point."""

from fastapi import FastAPI, HTTPException

from vlamguard.analyze import analyze
from vlamguard.engine.helm import HelmRenderError
from vlamguard.models.request import AnalyzeRequest, ReportRequest
from vlamguard.models.response import AnalyzeResponse
from vlamguard.models.report import ReportResponse
from vlamguard.integrations import IntegrationError
from vlamguard.integrations.platform import detect_platform
from vlamguard.integrations.issues import create_issue
from vlamguard.integrations.pull_requests import create_pull_request

app = FastAPI(
    title="VlamGuard",
    description="Intelligent change risk engine for infrastructure changes",
    version="1.0.0a2",
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/analyze", response_model=AnalyzeResponse)
async def analyze_endpoint(request: AnalyzeRequest) -> AnalyzeResponse:
    """Analyze a Helm chart for infrastructure risks."""
    try:
        return await analyze(request)
    except HelmRenderError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/report", response_model=ReportResponse)
async def report_endpoint(request: ReportRequest) -> ReportResponse:
    """Analyze and optionally create issues/PRs."""
    try:
        analysis = await analyze(request)
    except HelmRenderError as e:
        raise HTTPException(status_code=400, detail=str(e))

    issue_url = None
    pr_url = None

    try:
        if request.create_issues or request.create_pr:
            platform = detect_platform(
                remote=request.remote,
                platform_override=request.platform_override,
            )

        if request.create_issues:
            issue_url = create_issue(analysis, platform)

        if request.create_pr and request.manifests_path:
            pr_url = create_pull_request(
                analysis, platform, request.manifests_path,
                issue_url=issue_url,
            )
    except IntegrationError as e:
        raise HTTPException(status_code=422, detail=str(e))

    return ReportResponse(
        analysis=analysis,
        issue_url=issue_url,
        pr_url=pr_url,
    )
