# VlamGuard

[![CI](https://github.com/elky-bachtiar/VlamGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/elky-bachtiar/VlamGuard/actions/workflows/ci.yml)
[![Release](https://github.com/elky-bachtiar/VlamGuard/actions/workflows/release.yml/badge.svg)](https://github.com/elky-bachtiar/VlamGuard/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Intelligent change risk engine for infrastructure changes. Combines a deterministic policy engine with an AI-powered context layer to analyze Kubernetes/Helm deployments before they hit production.

## Installation

### Standalone binary (recommended for CI)

Download a pre-built binary from the [latest release](https://github.com/elky-bachtiar/VlamGuard/releases/latest) — no Python required:

| Platform | Binary |
|----------|--------|
| Linux (amd64) | `vlamguard-linux-amd64` |
| macOS (Intel) | `vlamguard-darwin-amd64` |
| macOS (Apple Silicon) | `vlamguard-darwin-arm64` |
| Windows (amd64) | `vlamguard-windows-amd64.exe` |

```bash
# Example: Linux
curl -Lo vlamguard https://github.com/elky-bachtiar/VlamGuard/releases/latest/download/vlamguard-linux-amd64
chmod +x vlamguard
./vlamguard --help
```

> **macOS note:** Unsigned binaries require `xattr -d com.apple.quarantine vlamguard` on first run.

### From source

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/getting-started/installation/).

```bash
git clone https://github.com/elky-bachtiar/VlamGuard.git && cd VlamGuard
uv sync
uv run vlamguard --help
```

### Prerequisites

- [Helm 3](https://helm.sh/docs/intro/install/) (for chart rendering)

Optional (for extended validation):

- [kube-score](https://github.com/zegl/kube-score) — extra validation layer
- [KubeLinter](https://github.com/stackrox/kube-linter) — security-focused checks
- [Polaris](https://github.com/FairwindsOps/polaris) — score-based validation benchmark

## CLI Usage

### Analyze a Helm chart

```bash
uv run vlamguard check --chart ./demo/charts/clean-deploy --env production --skip-ai
```

### Analyze pre-rendered manifests (no Helm needed)

```bash
uv run vlamguard check --manifests ./tests/fixtures/evident-risk.yaml --env production --skip-ai
```

### Discover and analyze all charts in a project

```bash
# Scan current directory recursively for Helm charts
uv run vlamguard discover . --skip-ai --skip-external

# Scan a specific directory with JSON output
uv run vlamguard discover ./infrastructure --output json

# Write summary to file
uv run vlamguard discover . --skip-ai --output markdown --output-file discovery-report.md
```

`discover` recursively finds all `Chart.yaml` files under the given root, runs risk analysis on each chart, and prints a summary table. Exits `1` if any chart is blocked, `0` otherwise. Skips `.git`, `node_modules`, `vendor`, and other non-project directories.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--chart` | — | Path to Helm chart directory |
| `--values` | — | Path to values YAML file |
| `--manifests` | — | Path to pre-rendered YAML (bypasses Helm) |
| `--env` | `production` | Target environment: `dev`, `staging`, `production` |
| `--skip-ai` | `false` | Skip AI context generation |
| `--skip-external` | `false` | Skip external tools (kube-score, KubeLinter, Polaris) |
| `--no-security-scan` | `false` | Disable secrets detection + extended checks + grading |
| `--waivers` | — | Path to waivers YAML file |
| `--output` | `terminal` | Output format: `terminal`, `json`, `markdown` |
| `--output-file` | — | Write report to file. With `terminal` output, writes markdown AND prints Rich terminal output (dual output) |

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

# Dual output: terminal + markdown file
uv run vlamguard check --manifests manifest.yaml --skip-ai --output-file report.md
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
Helm render → 79 Policy Checks → Secrets Detection → Risk Scoring → External Tools → AI Context → Report
```

Secrets detection feeds directly into risk scoring: confirmed secrets in production trigger hard blocks (score=100), while hard-pattern matches in non-production environments add +30 to the soft risk score per finding.

External tools run after scoring and before AI analysis. Their findings appear in a dedicated "External Tool Findings" section in the report. Polaris provides a compliance score shown side-by-side with VlamGuard's risk score.

### What VlamGuard adds

| | kube-score / KubeLinter / Polaris | VlamGuard |
|---|---|---|
| **Finds issues** | Yes | Yes |
| **Explains why** | Short hints | AI-generated context |
| **Impact analysis** | No | Yes |
| **Recommendations** | Generic | Structured: action + reason + resource + YAML snippet |
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
  "skip_external": false,
  "security_scan": true,
  "waivers_path": null
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
  "security_grade": "A",
  "security": {
    "secrets_detection": {...},
    "extended_checks": [...],
    "hardening_recommendations": [...]
  },
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

The chart's default Deployment passes all 79 VlamGuard policy checks in production mode (risk score 0/100, grade A). See `charts/vlamguard/values.yaml` for all options.

## AI Context (optional)

VlamGuard calls an OpenAI-compatible API for AI-powered analysis. Configure via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `VLAM_AI_BASE_URL` | `http://localhost:11434/v1` | API base URL |
| `VLAM_AI_MODEL` | `llama3.2` | Model name |
| `VLAM_AI_API_KEY` | — | Bearer token for authenticated backends |

Works with Ollama, vLLM, or any OpenAI-compatible endpoint. When unavailable or `--skip-ai` is set, VlamGuard runs policy checks only.

AI recommendations are structured objects with an action, reason (explaining *why* the change matters), target resource reference, and optional YAML snippet showing the exact fix. Plain string recommendations are also supported for backward compatibility.

AI responses are validated with both JSON Schema and Pydantic. Invalid or incomplete AI output is silently discarded — the deterministic engine always runs.

## Docker

```bash
docker compose up --build
```

The Docker image includes Helm, kube-score, KubeLinter, and Polaris pre-installed. The API server runs on `http://localhost:8000`.

Published images are available from GitHub Container Registry:

```bash
docker pull ghcr.io/elky-bachtiar/vlamguard:v1.0.0-alpha.1
docker pull ghcr.io/elky-bachtiar/vlamguard:latest
```

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

Eleven scenarios covering clean deploys, evident risks, subtle impacts, best-practice violations, hardened deployments, self-analysis, Polaris score comparison, CRD ecosystem checks, waiver workflow, compliance mapping, and AI-enhanced recommendations.

Each scenario outputs both Rich terminal display and a persistent markdown report to `demo/reports/`.

## Tests

```bash
uv run pytest              # all tests (1116)
uv run pytest --cov        # with coverage
uv run pytest tests/unit/  # unit + integration only
uv run pytest tests/e2e/   # E2E CLI tests (requires Helm)
```

## Policy Checks

VlamGuard runs 79 deterministic policy checks across eight categories. The behavior column describes production mode; non-production environments apply softer rules unless otherwise noted.

| Check | Severity | Production | Other Envs |
|-------|----------|-----------|------------|
| **Core Security** | | | |
| Image tag `:latest` or missing | critical | hard block | soft risk |
| Privileged container / no `runAsNonRoot` | critical | hard block | soft risk |
| Cluster-wide RBAC (`ClusterRoleBinding`) | critical | hard block | hard block |
| Read-only root filesystem | critical | hard block | soft risk |
| Non-root user and group (`runAsUser`/`runAsGroup` > 0) | critical | hard block | soft risk |
| Host namespace sharing | critical | hard block | soft risk |
| Dangerous volume mounts | critical | hard block | soft risk |
| Excessive Linux capabilities | high | soft risk | off |
| Service account token auto-mount | medium | soft risk | off |
| Exposed services (NodePort/LoadBalancer) | medium | soft risk | off |
| Allow privilege escalation | critical | hard block | soft risk |
| Host PID namespace sharing | critical | hard block | soft risk |
| Host IPC namespace sharing | critical | hard block | soft risk |
| Pod Security Standards | critical | hard block | soft risk |
| Drop all capabilities | high | soft risk | off |
| Ingress TLS | high | soft risk | off |
| Host port restriction | medium | soft risk | off |
| RBAC wildcard permissions | high | soft risk | soft risk |
| Automount service account token | medium | soft risk | off |
| **Reliability** | | | |
| Missing resource requests/limits | high | soft risk | off |
| Single replica deployment | high | soft risk | off |
| Missing liveness/readiness probes | high | soft risk | off |
| Deployment strategy (must be `RollingUpdate`) | high | soft risk | off |
| Pod disruption budget | high | soft risk | off |
| Pod anti-affinity (when replicas > 1) | high | soft risk | off |
| HPA target reference | medium | soft risk | off |
| **Best Practice** | | | |
| Image pull policy (must be `Always`) | medium | soft risk | off |
| Service type `NodePort` | medium | soft risk | off |
| NetworkPolicy validation | medium | soft risk | off |
| CronJob missing `startingDeadlineSeconds` | medium | soft risk | off |
| Deprecated API versions | medium | soft risk | soft risk |
| Duplicate environment variables | medium | soft risk | soft risk |
| Default namespace usage | medium | soft risk | soft risk |
| Container port name convention | low | soft risk | off |
| Resource quota | medium | soft risk | off |
| **Supply Chain** | | | |
| Image registry allowlist | high | soft risk | soft risk |
| **KEDA** | | | |
| Min replica count in production | high | soft risk | off |
| Fallback replica configuration required | high | soft risk | off |
| Authentication reference required | high | soft risk | off |
| HPA ownership validation | high | soft risk | off |
| Max replica bound | medium | soft risk | off |
| Trigger auth secrets | high | soft risk | off |
| Cooldown period | medium | soft risk | off |
| Polling interval | low | soft risk | off |
| Fallback replica range | medium | soft risk | off |
| Restore replicas on scale-down | medium | soft risk | off |
| Inline secret detection | critical | hard block | soft risk |
| Initial cooldown | low | soft risk | off |
| Job history limits | medium | soft risk | off |
| Paused annotation | medium | soft risk | soft risk |
| **Argo CD** | | | |
| Auto-sync with prune enabled | high | soft risk | soft risk |
| Sync retry configured | medium | soft risk | off |
| Destination not in-cluster | high | soft risk | soft risk |
| Project not default | medium | soft risk | soft risk |
| Source target revision pinned | high | soft risk | soft risk |
| Project wildcard destination | critical | hard block | soft risk |
| Project wildcard source | high | soft risk | soft risk |
| Project cluster resource access | high | soft risk | soft risk |
| **Istio** | | | |
| VirtualService timeout configured | high | soft risk | off |
| VirtualService retries configured | medium | soft risk | off |
| Fault injection in production | high | soft risk | off |
| DestinationRule TLS mode | critical | hard block | soft risk |
| DestinationRule outlier detection | medium | soft risk | off |
| DestinationRule connection pool | medium | soft risk | off |
| PeerAuthentication strict mTLS | critical | hard block | soft risk |
| AuthorizationPolicy no allow-all | high | soft risk | soft risk |
| Gateway TLS required | critical | hard block | soft risk |
| Gateway wildcard host | high | soft risk | soft risk |
| **cert-manager** | | | |
| Certificate duration | medium | soft risk | off |
| Certificate renew-before window | medium | soft risk | off |
| Certificate private key algorithm | high | soft risk | off |
| Wildcard certificate in production | high | soft risk | off |
| Issuer solver configured | high | soft risk | soft risk |
| Staging issuer in production | critical | hard block | soft risk |
| **External Secrets Operator** | | | |
| ExternalSecret refresh interval | medium | soft risk | off |
| ExternalSecret target creation policy | medium | soft risk | off |
| ExternalSecret deletion policy | high | soft risk | off |
| SecretStore provider configured | high | soft risk | soft risk |
| ClusterSecretStore conditions | medium | soft risk | off |

## Security Scan

The security scan layer goes beyond policy checks with secrets detection, extended security checks, and a letter grade (A-F). Enabled by default in `vlamguard check` (disable with `--no-security-scan`), or use the dedicated `vlamguard security-scan` command.

### Secrets Detection

Scans container env vars, command/args, ConfigMap data (including `envFrom configMapRef` cross-references), annotations, and Helm values for leaked credentials using regex patterns and Shannon entropy analysis.

**Hard patterns** (production = hard block, non-prod = +30 soft risk per finding):
`private_key`, `aws_access_key`, `aws_secret_key`, `github_token`, `database_url`, `generic_password_env`

**Soft patterns**: `suspicious_key_name`, `high_entropy_string`, `base64_in_configmap`

### Risk Scoring Integration

Secrets are integrated into VlamGuard's risk scoring engine:

| Environment | Confirmed secret (hard pattern) | Effect |
|-------------|--------------------------------|--------|
| `production` | Yes | **Hard block** — score=100, `blocked=true` |
| `dev`/`staging` | Yes (downgraded to soft risk) | **+30 per finding** to soft score |

### Security Grade

Deterministic F-to-A cascade based on secrets, extended checks, and AI hardening recommendations.

### Security Scan CLI

```bash
# Focused security scan
uv run vlamguard security-scan --chart ./demo/charts/security-scan-showcase --skip-ai

# Full check with security scan (default)
uv run vlamguard check --chart ./my-chart --skip-ai

# Disable security scan
uv run vlamguard check --chart ./my-chart --no-security-scan --skip-ai

# Apply waivers
uv run vlamguard check --chart ./my-chart --waivers ./waivers.yaml --skip-ai
uv run vlamguard security-scan --chart ./my-chart --waivers ./waivers.yaml --skip-ai
```

### Compliance Mapping

```bash
# List all policy checks with compliance tags
uv run vlamguard compliance

# Filter by framework
uv run vlamguard compliance --framework CIS
uv run vlamguard compliance --framework NSA
uv run vlamguard compliance --framework SOC2

# JSON output
uv run vlamguard compliance --output json
```

## Documentation

- [Full documentation](docs/README.md) — pipeline architecture, all 79 policy checks, security grading, API reference
- [Contributing guide](CONTRIBUTING.md) — development setup, code style, PR process
- [Changelog](CHANGELOG.md)
- [License](LICENSE) (Apache 2.0)
