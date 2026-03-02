"""FastAPI application entry point."""

from fastapi import FastAPI

app = FastAPI(
    title="VlamGuard",
    description="Intelligent change risk engine for infrastructure changes",
    version="0.1.0",
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
