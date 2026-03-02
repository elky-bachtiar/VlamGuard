# Build stage
FROM python:3.12-slim AS builder

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Copy dependency files first for layer caching
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Copy source and install project
COPY src/ src/
RUN uv sync --frozen --no-dev

# Runtime stage
FROM python:3.12-slim

# Install Helm
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash && \
    apt-get purge -y curl && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /app/.venv /app/.venv

# Add venv to PATH
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

# Default environment variables
ENV VLAM_AI_BASE_URL="http://host.docker.internal:11434/v1"
ENV VLAM_AI_MODEL="llama3.2"

EXPOSE 8000

# Default: run API server
CMD ["uvicorn", "vlamguard.main:app", "--host", "0.0.0.0", "--port", "8000"]
