# VlamGuard CLI Reference

Complete reference for all VlamGuard CLI commands and options.

---

## Overview

VlamGuard provides four commands:

| Command | Purpose |
|---------|---------|
| [`check`](#vlamguard-check) | Full risk analysis (policy checks + secrets + external tools + AI) |
| [`security-scan`](#vlamguard-security-scan) | Security-focused analysis (secrets + extended checks + grade) |
| [`compliance`](#vlamguard-compliance) | List policy checks with compliance framework mappings |
| [`discover`](#vlamguard-discover) | Recursively find and analyze all Helm charts in a directory tree |

All commands are invoked as subcommands of `vlamguard`:

```bash
vlamguard <command> [OPTIONS]
```

---

## `vlamguard check`

Run risk analysis on a Helm chart or pre-rendered manifests. Executes all 79 policy checks, optional secrets detection, optional external tools (kube-score, KubeLinter, Polaris), and optional AI context.

```bash
vlamguard check [OPTIONS]
```

### Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--chart PATH` | string | — | Path to Helm chart directory |
| `--values PATH` | string | — | Path to values YAML file |
| `--manifests PATH` | string | — | Path to pre-rendered YAML manifests (bypasses Helm) |
| `--env TEXT` | string | `production` | Target environment: `dev`, `staging`, `production` |
| `--skip-ai` | flag | off | Skip AI context generation |
| `--skip-external` | flag | off | Skip external tools (kube-score, KubeLinter, Polaris) |
| `--no-security-scan` | flag | off | Disable secrets detection + extended checks + grading |
| `--waivers PATH` | string | — | Path to waivers YAML file |
| `--output TEXT` | string | `terminal` | Output format: `terminal`, `json`, `markdown` |
| `--output-file PATH` | string | — | Write report to file |
| `--debug` | flag | off | Enable debug logging for AI requests |

> **Note:** Either `--chart` or `--manifests` is required. They are mutually exclusive.

### Examples

```bash
# Production analysis with all features
vlamguard check --chart ./my-chart --values ./prod-values.yaml

# Quick lint without AI or external tools
vlamguard check --chart ./my-chart --skip-ai --skip-external

# JSON output for CI pipelines
vlamguard check --chart ./my-chart --output json --output-file report.json --skip-ai

# Dev environment (lenient)
vlamguard check --manifests ./rendered.yaml --env dev --skip-ai

# Markdown report
vlamguard check --chart ./my-chart --output markdown --output-file report.md

# Dual output: terminal display + markdown file
vlamguard check --chart ./my-chart --skip-ai --output-file report.md

# Debug AI communication
vlamguard check --chart ./my-chart --debug

# Apply waivers to downgrade hard blocks
vlamguard check --chart ./my-chart --waivers ./waivers.yaml --skip-ai
```

---

## `vlamguard security-scan`

Security-focused analysis. Always enables secrets detection and extended security checks. Always skips external tools. Cannot disable security scanning.

```bash
vlamguard security-scan [OPTIONS]
```

### Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--chart PATH` | string | — | Path to Helm chart directory |
| `--values PATH` | string | — | Path to values YAML file |
| `--manifests PATH` | string | — | Path to pre-rendered YAML manifests (bypasses Helm) |
| `--env TEXT` | string | `production` | Target environment: `dev`, `staging`, `production` |
| `--skip-ai` | flag | off | Skip AI hardening recommendations |
| `--waivers PATH` | string | — | Path to waivers YAML file |
| `--output TEXT` | string | `terminal` | Output format: `terminal`, `json`, `markdown` |
| `--output-file PATH` | string | — | Write report to file |
| `--debug` | flag | off | Enable debug logging for AI requests |

> **Differences from `check`:** No `--skip-external` (always skips external tools). No `--no-security-scan` (security scan is always enabled). Produces a security grade (A-F).

### Examples

```bash
# Full security scan with AI hardening recommendations
vlamguard security-scan --chart ./my-chart

# Quick security scan, no AI, JSON output
vlamguard security-scan --chart ./my-chart --skip-ai --output json

# Security scan with waivers
vlamguard security-scan --chart ./my-chart --waivers ./waivers.yaml --skip-ai

# Debug AI requests
vlamguard security-scan --chart ./my-chart --debug
```

---

## `vlamguard compliance`

List all registered policy checks with their compliance framework mappings (CIS Kubernetes Benchmark, NSA Hardening Guide, SOC 2).

```bash
vlamguard compliance [OPTIONS]
```

### Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--framework TEXT` | string | — | Filter by framework: `CIS`, `NSA`, `SOC2` |
| `--output TEXT` | string | `terminal` | Output format: `terminal`, `json` |

### Output

**Terminal** — Rich table with columns: Check ID, Name, Severity, CIS, NSA, Tags. Shows total registered check count.

**JSON** — Array of objects with fields: `check_id`, `name`, `severity`, `category`, `compliance_tags`, `cis_benchmark`, `nsa_control`, `description`, `remediation`.

### Examples

```bash
# View all checks with compliance tags
vlamguard compliance

# Filter by CIS Kubernetes Benchmark
vlamguard compliance --framework CIS

# Filter by NSA Hardening Guide
vlamguard compliance --framework NSA

# SOC 2 controls
vlamguard compliance --framework SOC2

# JSON output for tooling integration
vlamguard compliance --output json
```

---

## `vlamguard discover`

Recursively find and analyze all Helm charts under a directory tree. Useful for mono-repos and platform repos with multiple charts.

```bash
vlamguard discover [ROOT] [OPTIONS]
```

### Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `ROOT` | argument | `.` | Root directory to scan for Helm charts |
| `--env TEXT` | string | `production` | Target environment: `dev`, `staging`, `production` |
| `--skip-ai` | flag | off | Skip AI context generation |
| `--skip-external` | flag | off | Skip external tools |
| `--no-security-scan` | flag | off | Disable security scan |
| `--waivers PATH` | string | — | Path to waivers YAML file |
| `--output TEXT` | string | `terminal` | Output format: `terminal`, `json`, `markdown` |
| `--output-file PATH` | string | — | Write report to file |
| `--debug` | flag | off | Enable debug logging for AI requests |

The command walks the directory tree looking for `Chart.yaml` files, skipping `.git`, `node_modules`, `vendor`, `__pycache__`, `.venv`, and similar non-project directories. Each discovered chart is analyzed independently, and a summary table is printed at the end.

### JSON Output Structure

```json
{
  "charts": [
    {"chart": "charts/app-a", "risk_score": 15, "risk_level": "low", "grade": "A", "blocked": false, "status": "PASS"},
    {"chart": "charts/app-b", "risk_score": null, "risk_level": null, "grade": null, "blocked": false, "status": "ERROR"}
  ],
  "summary": {"total": 2, "passed": 1, "blocked": 0, "errors": 1}
}
```

### Summary Table

In terminal/markdown mode, a summary table is printed after all charts are analyzed:

| Column | Description |
|--------|-------------|
| Chart | Relative path from root |
| Score | Risk score (0-100) or `-` on error |
| Grade | Security grade (A-F) or `-` |
| Status | `PASS`, `BLOCK`, or `ERROR` |

### Examples

```bash
# Scan current directory
vlamguard discover . --skip-ai --skip-external

# Scan a specific path with JSON output
vlamguard discover ./infrastructure --output json

# Write discovery report to file
vlamguard discover . --skip-ai --output markdown --output-file report.md

# Apply waivers across all discovered charts
vlamguard discover . --waivers ./waivers.yaml --skip-ai
```

---

## Output Formats

All commands that produce reports support multiple output formats via `--output`:

| Format | Description |
|--------|-------------|
| `terminal` | Rich-formatted with colors, tables, and panels (default) |
| `json` | Full Pydantic model serialization. Suitable for `jq`, CI artifacts, or programmatic consumption |
| `markdown` | Structured report with headers, tables, and sections. Good for PR comments or documentation |

### Dual Output

When `--output-file` is provided with terminal output (the default), VlamGuard writes a **markdown report** to the file AND displays the **Rich terminal output** — giving you both human-friendly console output and a persistent report.

```bash
# Terminal display + markdown file
vlamguard check --chart ./my-chart --skip-ai --output-file report.md
```

---

## Exit Codes

| Code | Meaning |
|:----:|---------|
| `0` | **Passed** — no hard blocks |
| `1` | **Blocked** — hard policy violations detected |
| `2` | **Error** — invalid input, missing flags, or Helm render failure |

---

## Environment Variables

VlamGuard uses environment variables to configure the AI context layer:

| Variable | Default | Description |
|----------|---------|-------------|
| `VLAM_AI_BASE_URL` | `http://localhost:11434/v1` | API base URL (Ollama default) |
| `VLAM_AI_MODEL` | `llama3.2` | Model name |
| `VLAM_AI_API_KEY` | — | Bearer token for authenticated endpoints |
| `VLAM_AI_TIMEOUT` | `120` | AI request timeout in seconds |

### Configuration Methods

**Option 1 — `.env` file (recommended):**

Create a `.env` file in the directory where you run VlamGuard. It is loaded automatically.

```
VLAM_AI_BASE_URL=https://api.openai.com/v1
VLAM_AI_MODEL=gpt-4o
VLAM_AI_API_KEY=sk-...
VLAM_AI_TIMEOUT=60
```

**Option 2 — Shell environment variables:**

```bash
# Linux / macOS
export VLAM_AI_API_KEY=sk-...

# Windows cmd
set VLAM_AI_API_KEY=sk-...

# Windows PowerShell
$env:VLAM_AI_API_KEY = "sk-..."
```

**Option 3 — Inline (Linux / macOS):**

```bash
VLAM_AI_API_KEY=sk-... vlamguard check --chart ./my-chart
```

Works with **Ollama**, **vLLM**, **OpenAI**, or any OpenAI-compatible endpoint. When unavailable or `--skip-ai` is set, VlamGuard runs policy checks only.
