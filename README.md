# VlamGuard

Intelligent change risk engine for infrastructure changes. Combines a deterministic policy engine with an AI-powered context layer to analyze Kubernetes/Helm deployments before they hit production.

## Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/getting-started/installation/)
- [Helm 3](https://helm.sh/docs/intro/install/) (for chart rendering)

Optional (for extended validation):

- [kube-score](https://github.com/zegl/kube-score) — extra validation layer
- [KubeLinter](https://github.com/stackrox/kube-linter) — security-focused checks
- [Polaris](https://github.com/FairwindsOps/polaris) — score-based validation benchmark

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
| `--skip-external` | `false` | Skip external tools (kube-score, KubeLinter, Polaris) |
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

## External Tool Integration

VlamGuard integrates with three established Kubernetes validation tools as supplementary validation layers. Each tool is called via subprocess and results are included in the report. When a tool is not installed, VlamGuard gracefully skips it.

| Tool | Role | Output |
|------|------|--------|
| **kube-score** | Broad static analysis (reliability + security) | Findings in report |
| **KubeLinter** | Security-focused checks (non-root, least privilege, secrets) | Findings in report |
| **Polaris** | Score-based compliance benchmark | Score comparison + findings |

### How it works

```
Helm render → VlamGuard policy engine (17 checks) → External tools → AI context → Report
```

External tools run after VlamGuard's own checks and before AI analysis. Their findings appear in a dedicated "External Tool Findings" section in the report. Polaris provides a compliance score shown side-by-side with VlamGuard's risk score.

### What VlamGuard adds

| | kube-score / KubeLinter / Polaris | VlamGuard |
|---|---|---|
| **Finds issues** | Yes | Yes |
| **Explains why** | Short hints | AI-generated context |
| **Impact analysis** | No | Yes |
| **Recommendations** | Generic | Contextual per deployment |
| **Rollback suggestion** | No | Yes |
| **Environment-aware** | No | Yes (production = strict) |
| **Pipeline gating** | Exit code only | Hard block + soft risk + scoring |

### Skip external tools

```bash
uv run vlamguard check --chart ./my-chart --skip-external
```

## API Server

```bash
uv run uvicorn vlamguard.main:app --reload
```

Endpoints:

- `GET /health` — health check
- `POST /api/v1/analyze` — analyze a Helm chart

### Request body

```json
{
  "chart": "./my-chart",
  "values": {"replicaCount": 3},
  "environment": "production",
  "skip_ai": false,
  "skip_external": false
}
```

### Response body

```json
{
  "risk_score": 0,
  "risk_level": "low",
  "blocked": false,
  "hard_blocks": [],
  "policy_checks": [...],
  "external_findings": [...],
  "polaris_score": 85,
  "ai_context": {...},
  "metadata": {...}
}
```

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

AI responses are validated with both JSON Schema and Pydantic. Invalid or incomplete AI output is silently discarded — the deterministic engine always runs.

## Docker

```bash
docker compose up --build
```

The Docker image includes Helm, kube-score, KubeLinter, and Polaris pre-installed. The API server runs on `http://localhost:8000`.

## CI/CD Integration

Example configs are provided in `ci/`:

### Jenkins

```groovy
// ci/Jenkinsfile
stage('VlamGuard Risk Analysis') {
    steps {
        sh 'vlamguard check --chart ./helm-chart --values ./values-${DEPLOY_ENV}.yaml --env ${DEPLOY_ENV} --output markdown --output-file vlamguard-report.md'
    }
}
```

### GitLab CI

```yaml
# ci/.gitlab-ci.yml
vlamguard-check:
  stage: test
  image: vlamguard:latest
  script:
    - vlamguard check --chart ./helm-chart --values ./values-${DEPLOY_ENV}.yaml --env ${DEPLOY_ENV} --output markdown --output-file vlamguard-report.md
```

## Demo

Run all demo scenarios:

```bash
bash demo/run_demo.sh
```

Seven scenarios covering clean deploys, evident risks, subtle impacts, best-practice violations, hardened deployments, self-analysis, and Polaris score comparison.

## Tests

```bash
uv run pytest              # all tests (184)
uv run pytest --cov        # with coverage
uv run pytest tests/unit/  # unit + integration only
uv run pytest tests/e2e/   # E2E CLI tests (requires Helm)
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
