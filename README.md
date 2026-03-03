# VlamGuard

Intelligent change risk engine for infrastructure changes. Combines a deterministic policy engine with an AI-powered context layer to analyze Kubernetes/Helm deployments before they hit production.

## Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/getting-started/installation/)
- [Helm 3](https://helm.sh/docs/intro/install/) (for chart rendering)

## Installation

```bash
# Clone and install
git clone <repo-url> && cd VlamGuard
uv sync

# Verify
uv run vlamguard --help
```

## CLI Usage

### Analyze a Helm chart

```bash
uv run vlamguard check --chart ./demo/charts/clean-deploy --env production --skip-ai
```

### Analyze pre-rendered manifests (no Helm needed)

```bash
uv run vlamguard check --manifests ./tests/fixtures/evident-risk.yaml --env production --skip-ai
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--chart` | — | Path to Helm chart directory |
| `--values` | — | Path to values YAML file |
| `--manifests` | — | Path to pre-rendered YAML (bypasses Helm) |
| `--env` | `production` | Target environment: `dev`, `staging`, `production` |
| `--skip-ai` | `false` | Skip AI context generation |
| `--output` | `terminal` | Output format: `terminal`, `json`, `markdown` |
| `--output-file` | — | Write report to file instead of stdout |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Passed — no hard blocks |
| `1` | Blocked — hard policy violations detected |
| `2` | Error — bad input or Helm failure |

### Output formats

```bash
# Rich terminal output (default)
uv run vlamguard check --manifests manifest.yaml --skip-ai

# JSON (for CI pipelines)
uv run vlamguard check --manifests manifest.yaml --skip-ai --output json

# Markdown report to file
uv run vlamguard check --manifests manifest.yaml --skip-ai --output markdown --output-file report.md
```

## API Server

```bash
uv run uvicorn vlamguard.main:app --reload
```

Endpoints:

- `GET /health` — health check
- `POST /api/v1/analyze` — analyze a Helm chart

## Helm Chart

Deploy VlamGuard into a Kubernetes cluster:

```bash
helm install vlamguard charts/vlamguard/
```

Override defaults with `--set` or a values file:

```bash
helm install vlamguard charts/vlamguard/ \
  --set ai.baseUrl="http://my-llm:8080/v1" \
  --set ai.model="gpt-4o" \
  --set ai.apiKeySecret.create=true \
  --set ai.apiKeySecret.apiKey="sk-..."
```

The chart's default Deployment passes all 17 VlamGuard policy checks in production mode (risk score 0/100). See `charts/vlamguard/values.yaml` for all options.

## AI Context (optional)

VlamGuard calls an OpenAI-compatible API for AI-powered analysis. Configure via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `VLAM_AI_BASE_URL` | `http://localhost:11434/v1` | API base URL |
| `VLAM_AI_MODEL` | `llama3.2` | Model name |
| `VLAM_AI_API_KEY` | — | Bearer token for authenticated backends |

Works with Ollama, vLLM, or any OpenAI-compatible endpoint. When unavailable or `--skip-ai` is set, VlamGuard runs policy checks only.

## Docker

```bash
docker compose up --build
```

The API server runs on `http://localhost:8000`.

## Tests

```bash
uv run pytest              # all tests
uv run pytest --cov        # with coverage
```

## Policy Checks

| Check | Severity | Production | Other Envs |
|-------|----------|-----------|------------|
| Image tag `:latest` or missing | critical | hard block | soft risk |
| Privileged container / no `runAsNonRoot` | critical | hard block | soft risk |
| Cluster-wide RBAC (`ClusterRoleBinding`) | critical | hard block | hard block |
| Read-only root filesystem | critical | hard block | soft risk |
| Non-root user and group (`runAsUser`/`runAsGroup` > 0) | critical | hard block | soft risk |
| Missing resource requests/limits | high | soft risk | off |
| Single replica deployment | high | soft risk | off |
| Missing liveness/readiness probes | high | soft risk | off |
| Deployment strategy (must be `RollingUpdate`) | high | soft risk | off |
| Pod disruption budget | high | soft risk | off |
| Pod anti-affinity (when replicas > 1) | high | soft risk | off |
| Image pull policy (must be `Always`) | medium | soft risk | off |
| Service type `NodePort` | medium | soft risk | off |
| NetworkPolicy validation | medium | soft risk | off |
| CronJob missing `startingDeadlineSeconds` | medium | soft risk | off |
| Deprecated API versions | medium | soft risk | soft risk |
| Duplicate environment variables | medium | soft risk | soft risk |
