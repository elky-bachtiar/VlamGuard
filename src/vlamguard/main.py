"""FastAPI application entry point."""

from fastapi import FastAPI, HTTPException

from vlamguard.analyze import analyze
from vlamguard.engine.helm import HelmRenderError
from vlamguard.models.request import AnalyzeRequest
from vlamguard.models.response import AnalyzeResponse

app = FastAPI(
    title="VlamGuard",
    description="Intelligent change risk engine for infrastructure changes",
    version="1.0.0a1",
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
