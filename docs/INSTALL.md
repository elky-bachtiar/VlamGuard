# VlamGuard Installation Guide

Complete guide for installing and using VlamGuard on Linux, macOS, and Windows.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [From Source (all platforms)](#from-source-all-platforms)
  - [Standalone Binary](#standalone-binary)
  - [Docker](#docker)
- [External Tools Setup](#external-tools-setup)
  - [kube-score](#kube-score)
  - [KubeLinter](#kubelinter)
  - [Polaris](#polaris)
- [AI Backend Configuration](#ai-backend-configuration)
  - [Using the Vlam AI Proxy](#using-the-vlam-ai-proxy)
  - [Using OpenAI Directly](#using-openai-directly)
  - [Using a Local Model (Ollama)](#using-a-local-model-ollama)
- [CLI Usage](#cli-usage)
- [API Server](#api-server)

---

## Prerequisites

- **Helm 3** — required for chart rendering ([install guide](https://helm.sh/docs/intro/install/))
- **Python 3.12+** and **uv** — required for source installs ([uv install guide](https://docs.astral.sh/uv/getting-started/installation/))

---

## Installation

### From Source (all platforms)

```bash
git clone https://github.com/elky-bachtiar/VlamGuard.git
cd VlamGuard
uv sync
```

Verify the install:

```bash
uv run vlamguard --help
```

**Linux / macOS:**

```bash
# Optional: install as a global tool
uv tool install .
vlamguard --help
```

**Windows (PowerShell):**

```powershell
git clone https://github.com/elky-bachtiar/VlamGuard.git
cd VlamGuard
uv sync
uv run vlamguard --help
```

### Standalone Binary

Download a pre-built binary from the [latest release](https://github.com/elky-bachtiar/VlamGuard/releases/latest) — no Python required.

**Linux (amd64):**

```bash
curl -Lo vlamguard https://github.com/elky-bachtiar/VlamGuard/releases/latest/download/vlamguard-linux-amd64
chmod +x vlamguard
sudo mv vlamguard /usr/local/bin/
vlamguard --help
```

**macOS (Apple Silicon):**

```bash
curl -Lo vlamguard https://github.com/elky-bachtiar/VlamGuard/releases/latest/download/vlamguard-darwin-arm64
chmod +x vlamguard
# Remove quarantine attribute (unsigned binary)
xattr -d com.apple.quarantine vlamguard
sudo mv vlamguard /usr/local/bin/
vlamguard --help
```

**Windows (amd64):**

```powershell
Invoke-WebRequest -Uri "https://github.com/elky-bachtiar/VlamGuard/releases/latest/download/vlamguard-windows-amd64.exe" -OutFile vlamguard.exe
.\vlamguard.exe --help
```

### Docker

```bash
docker pull ghcr.io/vlamguard/vlamguard:latest

# Run a check
docker run --rm -v $(pwd)/my-chart:/chart ghcr.io/vlamguard/vlamguard:latest \
  check --chart /chart --env production --skip-ai
```

The Docker image includes Helm, kube-score, KubeLinter, and Polaris pre-installed.

---

## External Tools Setup

VlamGuard integrates with three external Kubernetes linting tools. These are **optional** — VlamGuard runs its own 79 policy checks regardless. External tools provide additional validation and their findings are passed to the AI context layer.

Use `--skip-external` to skip external tools entirely.

### kube-score

**Linux:**

```bash
curl -Lo kube-score https://github.com/zegl/kube-score/releases/latest/download/kube-score_linux_amd64
chmod +x kube-score
sudo mv kube-score /usr/local/bin/
```

**macOS:**

```bash
brew install kube-score
```

**Windows:**

```powershell
scoop install kube-score
```

### KubeLinter

**Linux:**

```bash
curl -Lo kube-linter https://github.com/stackrox/kube-linter/releases/latest/download/kube-linter-linux
chmod +x kube-linter
sudo mv kube-linter /usr/local/bin/
```

**macOS:**

```bash
brew install kube-linter
```

**Windows:**

```powershell
scoop install kube-linter
```

### Polaris

**Linux:**

```bash
curl -Lo polaris https://github.com/FairwindsOps/polaris/releases/latest/download/polaris_linux_amd64
chmod +x polaris
sudo mv polaris /usr/local/bin/
```

**macOS:**

```bash
brew install FairwindsOps/tap/polaris
```

**Windows:**

Download from [Polaris releases](https://github.com/FairwindsOps/polaris/releases) and add to PATH.

### Verify External Tools

```bash
kube-score version
kube-linter version
polaris version
```

VlamGuard auto-detects which tools are available on `PATH` and uses them. Missing tools are silently skipped.

---

## AI Backend Configuration

VlamGuard uses an OpenAI-compatible API for AI-powered analysis. Configure via environment variables or a `.env` file in the project root.

| Variable | Description | Default |
|----------|-------------|---------|
| `VLAM_AI_BASE_URL` | Base URL of the AI API | `http://localhost:11434/v1` (Ollama) |
| `VLAM_AI_MODEL` | Model identifier | `llama3.2` |
| `VLAM_AI_API_KEY` | API key (Bearer token) | *(none)* |
| `VLAM_AI_TIMEOUT` | Request timeout in seconds | `120` |

### Using the Vlam AI Proxy

The vlam-proxy translates between OpenAI format and the Vlam AI backend.

1. Configure the proxy (see `vlam-proxy/.env`):

```env
VLAM_URL=https://api.demo.vlam.ai/v2.1/projects/poc/openai-compatible/v1
VLAM_KEY=your-vlam-api-key
```

2. Start the proxy:

```bash
cd vlam-proxy
pip install httpx fastapi uvicorn python-dotenv
python proxy.py
```

3. Configure VlamGuard `.env`:

```env
VLAM_AI_BASE_URL=http://localhost:8080/v1
VLAM_AI_MODEL=ubiops-deployment/ocw-ictswh2-mistralmedium-flexibel//chat-model
VLAM_AI_API_KEY=proxy
```

4. Run with AI enabled:

```bash
uv run vlamguard check --chart ./my-chart --env production --debug
```

### Using OpenAI Directly

```env
VLAM_AI_BASE_URL=https://api.openai.com/v1
VLAM_AI_MODEL=gpt-4o-mini
VLAM_AI_API_KEY=sk-your-openai-key
```

### Using a Local Model (Ollama)

1. Install [Ollama](https://ollama.ai) and pull a model:

```bash
ollama pull llama3.2
```

2. No `.env` changes needed — the defaults point to Ollama:

```bash
uv run vlamguard check --chart ./my-chart --env production
```

### Skip AI

To run without AI (policy checks only):

```bash
uv run vlamguard check --chart ./my-chart --env production --skip-ai
```

### Debugging AI Issues

Use `--debug` to see the full AI request/response lifecycle:

```bash
uv run vlamguard check --chart ./my-chart --env production --debug
```

Debug output (on stderr) shows:
- Request URL, model, and whether an API key is set
- Response HTTP status code
- Error details on connection failures, HTTP errors, or JSON parse errors
- Schema validation failures with the specific field and path

---

## CLI Usage

### Check a Helm chart

```bash
vlamguard check --chart ./my-chart --env production
```

### Check pre-rendered manifests

```bash
vlamguard check --manifests ./rendered.yaml --env production
```

### Security scan (secrets + extended checks + grade)

```bash
vlamguard security-scan --chart ./my-chart --env production
```

### Discover all charts in a directory

```bash
vlamguard discover ./infrastructure --env production
```

### Common options

| Flag | Description |
|------|-------------|
| `--env` | Target environment: `dev`, `staging`, `production` |
| `--skip-ai` | Skip AI context generation |
| `--skip-external` | Skip external tools (kube-score, KubeLinter, Polaris) |
| `--no-security-scan` | Disable secrets detection and security grading |
| `--debug` | Enable debug logging for AI requests |
| `--waivers <file>` | Apply waivers from a YAML file |
| `--output terminal\|json\|markdown` | Output format (default: `terminal`) |
| `--output-file <path>` | Write report to file (terminal mode also writes markdown) |

### Output formats

```bash
# JSON (for CI pipelines)
vlamguard check --chart ./my-chart --env production --output json

# Markdown report to file
vlamguard check --chart ./my-chart --env production --output-file report.md

# Compliance mapping
vlamguard compliance --framework CIS --output json
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | All checks passed, deployment is not blocked |
| `1` | Deployment is blocked (hard blocks or high risk score) |
| `2` | Input error (missing chart, invalid arguments) |

---

## API Server

Start the FastAPI server:

```bash
uv run uvicorn vlamguard.main:app --host 0.0.0.0 --port 8000
```

### Endpoints

**Health check:**

```bash
curl http://localhost:8000/health
```

**Analyze a chart:**

```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "chart_path": "./my-chart",
    "environment": "production",
    "skip_ai": false,
    "skip_external": true
  }'
```

The API returns the same `AnalyzeResponse` JSON as `vlamguard check --output json`.
