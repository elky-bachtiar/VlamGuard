# Build stage
FROM python:3.12-slim AS builder

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Copy dependency files first for layer caching
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Copy source and install project
COPY README.md ./
COPY src/ src/
RUN uv sync --frozen --no-dev

# Runtime stage
FROM python:3.12-slim

# Install Helm + external validation tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    # Helm
    curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash && \
    # kube-score
    curl -fsSL -o /tmp/kube-score.tar.gz \
        https://github.com/zegl/kube-score/releases/download/v1.19.0/kube-score_1.19.0_linux_amd64.tar.gz && \
    tar -xzf /tmp/kube-score.tar.gz -C /usr/local/bin kube-score && \
    chmod +x /usr/local/bin/kube-score && \
    rm /tmp/kube-score.tar.gz && \
    # kube-linter
    curl -fsSL -o /usr/local/bin/kube-linter \
        https://github.com/stackrox/kube-linter/releases/download/v0.7.1/kube-linter-linux && \
    chmod +x /usr/local/bin/kube-linter && \
    # Polaris
    curl -fsSL -o /tmp/polaris.tar.gz \
        https://github.com/FairwindsOps/polaris/releases/download/9.5.0/polaris_linux_amd64.tar.gz && \
    tar -xzf /tmp/polaris.tar.gz -C /usr/local/bin polaris && \
    chmod +x /usr/local/bin/polaris && \
    rm /tmp/polaris.tar.gz && \
    # Cleanup
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

USER 1000:1000

# Default: run API server
CMD ["uvicorn", "vlamguard.main:app", "--host", "0.0.0.0", "--port", "8000"]
