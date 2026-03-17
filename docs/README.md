<p align="center">
  <img src="vlamguard_logo.svg" alt="VlamGuard" width="280" />
</p>

<h1 align="center">VlamGuard Documentation</h1>

<p align="center">
  <strong>Intelligent Change Risk Engine for Kubernetes & Helm</strong><br/>
  Deterministic compliance with AI-enhanced interpretability
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#how-it-works">How It Works</a> &bull;
  <a href="#cli-reference">CLI Reference</a> &bull;
  <a href="#policy-checks">Policy Checks</a> &bull;
  <a href="#crd-policy-checks">CRD Policy Checks</a> &bull;
  <a href="#security-scan">Security Scan</a> &bull;
  <a href="#waiver-workflow">Waiver Workflow</a> &bull;
  <a href="#compliance-mapping">Compliance Mapping</a> &bull;
  <a href="#api-reference">API Reference</a> &bull;
  <a href="#configuration">Configuration</a>
</p>

---

## Table of Contents

- [What is VlamGuard?](#what-is-vlamguard)
- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
  - [The Pipeline](#the-pipeline)
  - [Risk Scoring](#risk-scoring)
  - [Environment-Aware Behavior](#environment-aware-behavior)
- [CLI Reference](#cli-reference)
  - [`vlamguard check`](#vlamguard-check)
  - [`vlamguard security-scan`](#vlamguard-security-scan)
  - [`vlamguard compliance`](#vlamguard-compliance)
  - [`vlamguard discover`](#vlamguard-discover)
  - [Output Formats](#output-formats)
  - [Exit Codes](#exit-codes)
- [Policy Checks](#policy-checks)
  - [Overview](#policy-checks-overview)
  - [Security Checks](#security-checks)
  - [Reliability Checks](#reliability-checks)
  - [Best-Practice Checks](#best-practice-checks)
  - [Quick Reference Table](#quick-reference-table)
- [CRD Policy Checks](#crd-policy-checks)
  - [KEDA Checks (15)](#keda-checks)
  - [Argo CD Checks (8)](#argocd-checks)
  - [Istio Checks (10)](#istio-checks)
  - [cert-manager Checks (6)](#cert-manager-checks)
  - [External Secrets Operator Checks (5)](#external-secrets-operator-checks)
- [Security Scan](#security-scan)
  - [Secrets Detection](#secrets-detection)
  - [Extended Security Checks](#extended-security-checks)
  - [Security Grading (A-F)](#security-grading-a-f)
- [Waiver Workflow](#waiver-workflow)
- [Compliance Mapping](#compliance-mapping)
- [External Tools](#external-tools)
- [AI Context Layer](#ai-context-layer)
- [API Reference](#api-reference)
- [Configuration](#configuration)
- [CI/CD Integration](#cicd-integration)
- [Deployment](#deployment)
  - [Standalone Binaries](#standalone-binaries)
  - [Docker](#docker)
  - [Helm](#helm-self-deploy)

---

## What is VlamGuard?

VlamGuard analyzes Kubernetes and Helm deployments **before they reach production**. It combines three layers:

| Layer | What it does | Always runs? |
|-------|-------------|:---:|
| **Deterministic Policy Engine** | 79 built-in checks across security, reliability, and best practices | Yes |
| **Secrets & Security Scanner** | Regex + entropy-based credential detection, security grading | Yes (opt-out) |
| **AI Context Layer** | Natural-language impact analysis, recommendations, rollback suggestions | Optional |

Unlike traditional linters that only flag issues, VlamGuard provides **environment-aware scoring** (production is strict, dev is lenient), **pipeline gating** (hard blocks stop deployments), and **AI-powered context** that explains *why* something matters and *what to do about it*.

### What VlamGuard adds over existing tools

| Capability | kube-score / KubeLinter / Polaris | VlamGuard |
|---|:---:|:---:|
| Find issues | Yes | Yes |
| Explain impact | Short hints | AI-generated narrative |
| Impact analysis | No | Per-resource severity |
| Contextual recommendations | Generic | Tailored to your deployment |
| Rollback suggestion | No | Yes |
| Environment-aware strictness | No | Yes |
| Secrets detection | No | Regex + entropy |
| Pipeline gating | Exit code only | Hard block + soft risk + scoring |
| Security grading (A-F) | No | Yes |

---

## Quick Start

### Option A: Standalone binary (no Python required)

Download a pre-built binary from the [latest release](https://github.com/elky-bachtiar/VlamGuard/releases/latest):

| Platform | Binary |
|----------|--------|
| Linux (amd64) | `vlamguard-linux-amd64` |
| macOS (Apple Silicon) | `vlamguard-darwin-arm64` |
| Windows (amd64) | `vlamguard-windows-amd64.exe` |

```bash
# Example: Linux
curl -Lo vlamguard https://github.com/elky-bachtiar/VlamGuard/releases/latest/download/vlamguard-linux-amd64
chmod +x vlamguard
./vlamguard --help
```

> **macOS Gatekeeper:** Unsigned binaries require `xattr -d com.apple.quarantine vlamguard` on first run.
>
> **Windows Defender:** PyInstaller binaries may be flagged; this is a known false positive.

### Option B: From source

Prerequisites:

- Python 3.12+
- [uv](https://docs.astral.sh/uv/getting-started/installation/) (recommended) or pip
- [Helm 3](https://helm.sh/docs/intro/install/) (for chart rendering)

```bash
git clone https://github.com/elky-bachtiar/VlamGuard.git && cd VlamGuard
uv sync
uv run vlamguard --help
```

### Your first scan

```bash
# Analyze a Helm chart against production policies
uv run vlamguard check --chart ./demo/charts/clean-deploy --env production --skip-ai

# Analyze pre-rendered manifests (no Helm needed)
uv run vlamguard check --manifests ./tests/fixtures/evident-risk.yaml --skip-ai

# Run a focused security scan
uv run vlamguard security-scan --chart ./demo/charts/security-scan-showcase --skip-ai
```

---

## How It Works

### The Pipeline

Every analysis follows this sequence:

```
                    +-------------------+
                    |   Helm Chart or   |
                    |  Raw Manifests    |
                    +--------+----------+
                             |
                    Step 1   |  Render (helm template)
                             v
                    +-------------------+
                    | Parsed Manifests  |  list of Kubernetes resources
                    +--------+----------+
                             |
                    Step 2   |  79 Policy Checks
                             v
                    +-------------------+
                    | Policy Results    |  pass/fail per check per resource
                    +--------+----------+
                             |
                    Step 3   |  Secrets Detection (if security_scan=true)
                             v
                    +-------------------+
                    | Secret Findings   |  hard blocks + soft risks
                    +--------+----------+
                             |
                    Step 4   |  Risk Scoring (policy checks + secrets)
                             v
                    +-------------------+
                    | Risk Score 0-100  |  LOW / MEDIUM / HIGH / CRITICAL
                    +--------+----------+
                             |
                    Step 5   |  External Tools (optional)
                             v
                    +-------------------+
                    | External Findings |  kube-score, KubeLinter, Polaris
                    +--------+----------+
                             |
                    Step 6   |  AI Context (optional)
                             |  receives policy results + external findings
                             v
                    +-------------------+
                    | AI Analysis       |  summary, impact, recommendations
                    +--------+----------+
                             |
                    Step 7   |  Security Grade (if security_scan=true)
                             v
                    +-------------------+
                    | Final Report      |  A/B/C/D/F grade
                    +-------------------+
```

### Risk Scoring

Policy check failures accumulate **risk points**. The total determines the risk level:

| Score | Level | Blocked? |
|:-----:|:-----:|:--------:|
| 0 - 30 | **LOW** | No |
| 31 - 60 | **MEDIUM** | No |
| 61 - 100 | **HIGH** | Yes |
| Any hard block | **CRITICAL** | Yes (forced to 100) |

A single hard-block check failure immediately sets the score to 100 and blocks the deployment.

#### Secrets in Risk Scoring

Secrets detection results feed directly into the risk scoring engine:

| Environment | Confirmed secret (hard pattern match) | Effect on score |
|-------------|--------------------------------------|-----------------|
| `production` | Hard block | Score = **100**, `blocked = true`. Each finding appears in `hard_blocks` as `"Secrets Detection: {type} at {location}"`. |
| `dev` / `staging` | Soft risk (+30 per finding) | Each hard-pattern finding that was downgraded to a soft risk adds **+30 points** to the soft score. Multiple secrets accumulate (e.g., 2 findings = +60). |

This means a deployment with a confirmed hardcoded production secret (e.g., a `DATABASE_URL` with embedded credentials) will **always be blocked**, even if all 79 policy checks pass.

### Environment-Aware Behavior

VlamGuard uses a binary strictness model based on the `--env` flag:

| Environment | Behavior |
|------------|----------|
| `production` | Maximum strictness. Security checks trigger **hard blocks**. All checks active. |
| `dev` / `staging` / anything else | Lenient. Security checks become **soft risks** (points-based). Reliability and best-practice checks are **off**. |

This means the same chart can pass in dev but fail in production — exactly what you want for a progressive deployment pipeline.

---

## CLI Reference

### `vlamguard check`

Full risk analysis. Runs all 79 policy checks, optional secrets detection, optional external tools, optional AI context.

```bash
vlamguard check [OPTIONS]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--chart PATH` | string | — | Path to Helm chart directory |
| `--values PATH` | string | — | Path to values YAML file |
| `--manifests PATH` | string | — | Path to pre-rendered YAML (bypasses Helm) |
| `--env TEXT` | string | `production` | Target environment |
| `--skip-ai` | flag | off | Skip AI context generation |
| `--skip-external` | flag | off | Skip external tools |
| `--no-security-scan` | flag | off | Disable secrets detection + extended checks + grading |
| `--waivers PATH` | string | — | Path to waiver YAML file |
| `--output TEXT` | string | `terminal` | Output format: `terminal`, `json`, `markdown` |
| `--output-file PATH` | string | — | Write output to file |
| `--debug` | flag | off | Enable debug logging for AI requests |

> **Note:** Either `--chart` or `--manifests` is required. They are mutually exclusive.

#### Examples

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
```

### `vlamguard security-scan`

Security-focused analysis. Always enables secrets detection and extended security checks. Always skips external tools. Cannot disable security scanning.

```bash
vlamguard security-scan [OPTIONS]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--chart PATH` | string | — | Path to Helm chart directory |
| `--values PATH` | string | — | Path to values YAML file |
| `--manifests PATH` | string | — | Path to pre-rendered YAML |
| `--env TEXT` | string | `production` | Target environment |
| `--skip-ai` | flag | off | Skip AI hardening recommendations |
| `--waivers PATH` | string | — | Path to waiver YAML file |
| `--output TEXT` | string | `terminal` | Output format |
| `--output-file PATH` | string | — | Write output to file |
| `--debug` | flag | off | Enable debug logging for AI requests |

#### Examples

```bash
# Full security scan with AI hardening recommendations
vlamguard security-scan --chart ./my-chart

# Quick security scan, no AI
vlamguard security-scan --chart ./my-chart --skip-ai --output json
```

### `vlamguard compliance`

List all policy checks with their compliance framework mappings.

```bash
vlamguard compliance [OPTIONS]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--framework TEXT` | string | — | Filter by framework: `CIS`, `NSA`, `SOC2` |
| `--output TEXT` | string | `terminal` | Output format: `terminal`, `json` |

#### Examples

```bash
# View all checks with compliance tags
vlamguard compliance

# Filter by framework
vlamguard compliance --framework CIS
vlamguard compliance --framework NSA
vlamguard compliance --framework SOC2

# JSON output for tooling
vlamguard compliance --output json
```

### `vlamguard discover`

Recursively find and analyze all Helm charts under a directory tree. Useful for mono-repos and platform repos with multiple charts.

```bash
vlamguard discover [ROOT] [OPTIONS]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `ROOT` | argument | `.` | Root directory to scan for Helm charts |
| `--env TEXT` | string | `production` | Target environment: `dev`, `staging`, `production` |
| `--skip-ai` | flag | `false` | Skip AI context generation |
| `--skip-external` | flag | `false` | Skip external tools |
| `--no-security-scan` | flag | `false` | Disable security scan |
| `--waivers TEXT` | string | — | Path to waivers YAML file |
| `--output TEXT` | string | `terminal` | Output format: `terminal`, `json`, `markdown` |
| `--output-file TEXT` | string | — | Write report to file |
| `--debug` | flag | off | Enable debug logging for AI requests |

The command walks the directory tree looking for `Chart.yaml` files, skipping `.git`, `node_modules`, `vendor`, `__pycache__`, `.venv`, and similar non-project directories. Each discovered chart is analyzed independently, and a summary table is printed at the end.

**Exit codes:** `0` if all charts pass, `1` if any chart is blocked. Charts that fail to render are reported as `ERROR` but do not block the others.

#### Examples

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

#### JSON Output Structure

```json
{
  "charts": [
    {"chart": "charts/app-a", "risk_score": 15, "risk_level": "low", "grade": "A", "blocked": false, "status": "PASS"},
    {"chart": "charts/app-b", "risk_score": null, "risk_level": null, "grade": null, "blocked": false, "status": "ERROR"}
  ],
  "summary": {"total": 2, "passed": 1, "blocked": 0, "errors": 1}
}
```

### Output Formats

**Terminal** (default) — Rich-formatted with colors, tables, and panels:
- Risk score panel with color-coded severity
- Policy checks table
- Secrets findings with severity indicators
- Hardening recommendations with resource references and YAML hints
- AI analysis panel with structured recommendations (action, reason, resource, YAML snippet)

When `--output-file` is provided with terminal output, VlamGuard writes a markdown report to the file AND displays the Rich terminal output — dual output for both human review and persistent records.

**JSON** — Full Pydantic model serialization. Suitable for `jq`, CI artifacts, or programmatic consumption.

**Markdown** — Structured report with headers, tables, and sections. Good for PR comments or documentation.

### Exit Codes

| Code | Meaning |
|:----:|---------|
| `0` | **Passed** — no hard blocks, risk within threshold |
| `1` | **Blocked** — hard policy violations or risk score > 60 |
| `2` | **Error** — invalid input, missing flags, or Helm render failure |

---

## Policy Checks

<a id="policy-checks-overview"></a>

VlamGuard runs 79 policy checks organized across core categories and CRD ecosystems. Each check is registered via a `@policy_check` decorator and runs against every applicable Kubernetes resource in your manifests. The 22 original checks cover standard Kubernetes workloads; 14 additional P0 enterprise checks extend coverage for RBAC, networking, and compliance; and 43 CRD-aware checks cover KEDA, Argo CD, Istio, cert-manager, and External Secrets Operator.

### Security Checks

These checks protect against container escape, privilege escalation, and unauthorized access.

---

#### `image_tag` — Image Tag Policy

| | |
|---|---|
| **Severity** | Critical &bull; 25 risk points |
| **Production** | Hard block |
| **Other envs** | Soft risk |

**What it checks:** Every container image across Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, and ReplicaSets.

**Fails when:**
- Image has no tag (e.g., `nginx` instead of `nginx:1.25.3`)
- Image uses the `:latest` tag

**Why it matters:** Mutable or unversioned images make deployments non-deterministic. A `docker pull` could silently fetch completely different code. In a production incident, you can't reliably identify which version is running.

**How to fix:**
```yaml
# Bad
image: nginx:latest
image: nginx

# Good
image: nginx:1.25.3
image: myapp:v2.1.0-sha-abc1234
```

---

#### `security_context` — Security Context

| | |
|---|---|
| **Severity** | Critical &bull; 25 risk points |
| **Production** | Hard block |
| **Other envs** | Soft risk |

**What it checks:** The `securityContext` field on every container.

**Fails when:**
- Container has no `securityContext` at all
- `privileged: true` is set
- `runAsNonRoot: true` is not set

**Why it matters:** Privileged containers and root-running containers are the two most common container escape vectors. A privileged container has nearly full access to the host kernel.

**How to fix:**
```yaml
securityContext:
  runAsNonRoot: true
  privileged: false          # or simply omit (false is default)
  allowPrivilegeEscalation: false
```

---

#### `rbac_scope` — RBAC Scope

| | |
|---|---|
| **Severity** | Critical &bull; 0 risk points (always hard blocks) |
| **Production** | Hard block |
| **Other envs** | **Hard block** (strictest check — blocks everywhere) |

**What it checks:** `ClusterRoleBinding` resources.

**Fails when:** A ClusterRoleBinding binds a ClusterRole to the `default` ServiceAccount.

**Why it matters:** The `default` ServiceAccount exists in every namespace and is automatically mounted into pods that don't specify a custom SA. Binding cluster-wide permissions to it grants those permissions to *every pod in the namespace* — an enormous blast radius.

**How to fix:**
```yaml
# Bad — binds to the default service account
subjects:
  - kind: ServiceAccount
    name: default

# Good — use a dedicated service account
subjects:
  - kind: ServiceAccount
    name: my-app-sa
```

---

#### `readonly_root_fs` — Read-Only Root Filesystem

| | |
|---|---|
| **Severity** | Critical &bull; 20 risk points |
| **Production** | Hard block |
| **Other envs** | Soft risk |

**What it checks:** `securityContext.readOnlyRootFilesystem` on every container.

**Fails when:** `readOnlyRootFilesystem: true` is not set.

**Why it matters:** A writable root filesystem allows attackers to persist malware, modify binaries, plant backdoors, or exfiltrate data to disk. Making it read-only forces applications to use explicit `emptyDir` or `tmpfs` mounts for writeable paths.

**How to fix:**
```yaml
securityContext:
  readOnlyRootFilesystem: true
# Use emptyDir for paths that need writes:
volumeMounts:
  - name: tmp
    mountPath: /tmp
volumes:
  - name: tmp
    emptyDir: {}
```

---

#### `run_as_user_group` — Run As User/Group

| | |
|---|---|
| **Severity** | Critical &bull; 20 risk points |
| **Production** | Hard block |
| **Other envs** | Soft risk |

**What it checks:** `runAsUser` and `runAsGroup` at pod or container level.

**Fails when:**
- `runAsUser` is not set or is 0 (root)
- `runAsGroup` is not set or is 0 (root)

**Why it matters:** Complements `runAsNonRoot` by explicitly anchoring UID/GID to non-zero values. Prevents privilege escalation through user namespace mismatches.

**How to fix:**
```yaml
securityContext:
  runAsUser: 1000
  runAsGroup: 1000
  runAsNonRoot: true
```

---

### Reliability Checks

These checks ensure your workloads survive failures, scale correctly, and don't starve the cluster.

---

#### `resource_limits` — Resource Limits

| | |
|---|---|
| **Severity** | High &bull; 25 risk points |
| **Production** | Soft risk |
| **Other envs** | Off |

**What it checks:** `resources` block on every container.

**Fails when:** Any of `requests.cpu`, `requests.memory`, `limits.cpu`, or `limits.memory` is missing.

**Why it matters:** Without limits, a runaway container can consume all node resources, starving other workloads. Without requests, the Kubernetes scheduler can't make reliable placement decisions, leading to overcommitted nodes.

**How to fix:**
```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 512Mi
```

---

#### `replica_count` — Replica Count

| | |
|---|---|
| **Severity** | High &bull; 30 risk points |
| **Production** | Soft risk |
| **Other envs** | Off |

**What it checks:** `spec.replicas` on Deployments, StatefulSets, and ReplicaSets.

**Fails when:** `replicas < 2` (defaults to 1 if unset).

**Why it matters:** A single replica has zero fault tolerance. A node drain, pod eviction, or crash causes downtime until the replacement starts.

**How to fix:**
```yaml
spec:
  replicas: 3  # or at least 2
```

---

#### `liveness_readiness_probes` — Liveness & Readiness Probes

| | |
|---|---|
| **Severity** | High &bull; 25 risk points |
| **Production** | Soft risk |
| **Other envs** | Off |

**What it checks:** `livenessProbe` and `readinessProbe` on every container.

**Fails when:** Either probe is missing.

**Why it matters:** Without a readiness probe, Kubernetes sends traffic to pods before they're ready — causing errors during startup. Without a liveness probe, deadlocked or hung pods are never restarted.

**How to fix:**
```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 30
readinessProbe:
  httpGet:
    path: /ready
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
```

---

#### `deployment_strategy` — Deployment Strategy

| | |
|---|---|
| **Severity** | High &bull; 20 risk points |
| **Production** | Soft risk |
| **Other envs** | Off |

**What it checks:** `spec.strategy.type` on Deployments.

**Fails when:** Strategy is anything other than `RollingUpdate` (e.g., `Recreate`).

**Why it matters:** `Recreate` terminates all pods before starting new ones, causing guaranteed downtime during every deploy. `RollingUpdate` replaces pods incrementally.

**How to fix:**
```yaml
spec:
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
```

---

#### `pod_disruption_budget` — Pod Disruption Budget

| | |
|---|---|
| **Severity** | High &bull; 15 risk points |
| **Production** | Soft risk |
| **Other envs** | Off |

**What it checks:** `PodDisruptionBudget` resources.

**Fails when:** PDB has neither `minAvailable` nor `maxUnavailable`.

**Why it matters:** A PDB without constraints provides no disruption protection during node drains, maintenance windows, or cluster autoscaling events.

**How to fix:**
```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
spec:
  minAvailable: 1        # or maxUnavailable: 1
  selector:
    matchLabels:
      app: my-app
```

---

#### `host_pod_anti_affinity` — Pod Anti-Affinity

| | |
|---|---|
| **Severity** | High &bull; 20 risk points |
| **Production** | Soft risk |
| **Other envs** | Off |

**What it checks:** `podAntiAffinity` on workloads with `replicas > 1`.

**Fails when:** Multiple replicas exist but no `podAntiAffinity` is configured.

**Why it matters:** Without anti-affinity, the scheduler can place all replicas on the same node. A single node failure takes down your entire service.

**How to fix:**
```yaml
spec:
  template:
    spec:
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                labelSelector:
                  matchLabels:
                    app: my-app
                topologyKey: kubernetes.io/hostname
```

---

### Best-Practice Checks

These checks enforce operational hygiene and forward-compatibility.

---

#### `image_pull_policy` — Image Pull Policy

| | |
|---|---|
| **Severity** | Medium &bull; 10 risk points |
| **Production** | Soft risk |
| **Other envs** | Off |

**What it checks:** `imagePullPolicy` on every container.

**Fails when:** `imagePullPolicy` is not `Always`.

**Why it matters:** `IfNotPresent` can serve a stale cached image, bypassing security patches. `Always` ensures the registry is checked on every pod start.

---

#### `service_type` — Service Type

| | |
|---|---|
| **Severity** | Medium &bull; 15 risk points |
| **Production** | Soft risk |
| **Other envs** | Off |

**What it checks:** `spec.type` on Services.

**Fails when:** Service type is `NodePort`.

**Why it matters:** NodePort exposes services on all node IPs on a high port, bypassing ingress controllers and typical firewall rules. Use `ClusterIP` with an Ingress instead.

---

#### `network_policy` — Network Policy

| | |
|---|---|
| **Severity** | Medium &bull; 10 risk points |
| **Production** | Soft risk |
| **Other envs** | Off |

**What it checks:** `NetworkPolicy` resources.

**Fails when:** `podSelector` is missing, or neither `ingress` nor `egress` rules are defined.

**Why it matters:** A NetworkPolicy without selectors or rules is effectively inert — it provides no traffic isolation.

---

#### `cronjob_deadline` — CronJob Deadline

| | |
|---|---|
| **Severity** | Medium &bull; 10 risk points |
| **Production** | Soft risk |
| **Other envs** | Off |

**What it checks:** `startingDeadlineSeconds` on CronJobs.

**Fails when:** `startingDeadlineSeconds` is absent.

**Why it matters:** Without a deadline, missed schedules accumulate and can flood the system when the scheduler catches up, creating job storms.

---

#### `stable_api_version` — Stable API Version

| | |
|---|---|
| **Severity** | Medium &bull; 15 risk points |
| **Production** | Soft risk |
| **Other envs** | **Soft risk** (active everywhere) |

**What it checks:** `apiVersion` on every resource.

**Fails when:** `apiVersion` is in the deprecated list:
- `extensions/v1beta1`, `apps/v1beta1`, `apps/v1beta2`
- `networking.k8s.io/v1beta1`, `policy/v1beta1`
- `rbac.authorization.k8s.io/v1beta1`
- `admissionregistration.k8s.io/v1beta1`
- `apiextensions.k8s.io/v1beta1`, `storage.k8s.io/v1beta1`

**Why it matters:** Deprecated APIs are removed in newer Kubernetes versions. Using them creates silent upgrade blockers.

---

#### `env_var_duplicates` — Env Var Duplicates

| | |
|---|---|
| **Severity** | Medium &bull; 10 risk points |
| **Production** | Soft risk |
| **Other envs** | **Soft risk** (active everywhere) |

**What it checks:** `env` array on every container.

**Fails when:** The same environment variable name appears more than once.

**Why it matters:** Kubernetes uses the last value for duplicates — silent shadowing creates unpredictable behavior and is almost always a configuration bug.

---

### Quick Reference Table

#### Core Checks (1-22)

| # | Check | Category | Severity | Points | Production | Other |
|:-:|-------|----------|:--------:|:------:|:----------:|:-----:|
| 1 | `image_tag` | Security | Critical | 25 | Hard block | Soft risk |
| 2 | `security_context` | Security | Critical | 25 | Hard block | Soft risk |
| 3 | `rbac_scope` | Security | Critical | 0 | Hard block | Hard block |
| 4 | `readonly_root_fs` | Security | Critical | 20 | Hard block | Soft risk |
| 5 | `run_as_user_group` | Security | Critical | 20 | Hard block | Soft risk |
| 6 | `resource_limits` | Reliability | High | 25 | Soft risk | Off |
| 7 | `replica_count` | Reliability | High | 30 | Soft risk | Off |
| 8 | `liveness_readiness_probes` | Reliability | High | 25 | Soft risk | Off |
| 9 | `deployment_strategy` | Reliability | High | 20 | Soft risk | Off |
| 10 | `pod_disruption_budget` | Reliability | High | 15 | Soft risk | Off |
| 11 | `host_pod_anti_affinity` | Reliability | High | 20 | Soft risk | Off |
| 12 | `image_pull_policy` | Best practice | Medium | 10 | Soft risk | Off |
| 13 | `service_type` | Best practice | Medium | 15 | Soft risk | Off |
| 14 | `network_policy` | Best practice | Medium | 10 | Soft risk | Off |
| 15 | `cronjob_deadline` | Best practice | Medium | 10 | Soft risk | Off |
| 16 | `stable_api_version` | Best practice | Medium | 15 | Soft risk | Soft risk |
| 17 | `env_var_duplicates` | Best practice | Medium | 10 | Soft risk | Soft risk |
| 18 | `host_namespace` | Security | Critical | 30 | Hard block | Soft risk |
| 19 | `dangerous_volume_mounts` | Security | Critical | 30 | Hard block | Soft risk |
| 20 | `excessive_capabilities` | Security | High | 20 | Soft risk | Off |
| 21 | `service_account_token` | Security | Medium | 10 | Soft risk | Off |
| 22 | `exposed_services` | Security | Medium | 15 | Soft risk | Off |

#### P0 Enterprise Checks (23-36)

| # | Check | Compliance | Severity | Points | Production | Other |
|:-:|-------|-----------|:--------:|:------:|:----------:|:-----:|
| 23 | `allow_privilege_escalation` | CIS-5.2.5, NSA-3.1 | Critical | 20 | Hard block | Soft risk |
| 24 | `host_pid` | CIS-5.2.2 | Critical | 25 | Hard block | Soft risk |
| 25 | `host_ipc` | CIS-5.2.3 | Critical | 25 | Hard block | Soft risk |
| 26 | `default_namespace` | CIS-5.7.4 | Medium | 10 | Soft risk | Off |
| 27 | `pod_security_standards` | CIS-5.2, NSA-3.1 | High | 25 | Soft risk | Off |
| 28 | `drop_all_capabilities` | CIS-5.2.7, CIS-5.2.9, NSA-3.1 | High | 20 | Soft risk | Off |
| 29 | `ingress_tls` | SOC2-CC6.6 | Medium | 15 | Soft risk | Off |
| 30 | `host_port_restriction` | CIS-5.2.2 | Medium | 10 | Soft risk | Soft risk |
| 31 | `rbac_wildcard_permissions` | CIS-5.1.3 | Critical | 0 | Hard block | Hard block |
| 32 | `image_registry_allowlist` | SOC2-CC6.1 | Medium | 10 | Soft risk | Off |
| 33 | `container_port_name` | — | Medium | 5 | Soft risk | Off |
| 34 | `automount_service_account` | CIS-5.1.5 | Medium | 10 | Soft risk | Off |
| 35 | `hpa_target_ref` | — | Medium | 10 | Soft risk | Off |
| 36 | `resource_quota` | SOC2-CC7.2 | Medium | 10 | Soft risk | Off |

> CRD-specific checks (KEDA, Argo CD, Istio, cert-manager, ESO) are listed in [CRD Policy Checks](#crd-policy-checks) below.

---

## CRD Policy Checks

VlamGuard includes 43 CRD-aware checks that activate when the relevant custom resources are present in the rendered manifests. These checks are skipped silently when the corresponding CRD is not in use.

### KEDA Checks

14 checks for [KEDA](https://keda.sh/) `ScaledObject` and `ScaledJob` resources.

| # | Check ID | Compliance | Severity | Points | Production | Other |
|:-:|----------|-----------|:--------:|:------:|:----------:|:-----:|
| 37 | `keda_min_replica_production` | SOC2-CC7.5 | High | 20 | Soft risk | Off |
| 38 | `keda_fallback_required` | SOC2-CC7.5 | High | 20 | Soft risk | Off |
| 39 | `keda_auth_ref_required` | CIS-5.4.1, SOC2-CC6.1 | High | 20 | Hard block | Soft risk |
| 40 | `keda_hpa_ownership_validation` | — | High | 15 | Soft risk | Off |
| 41 | `keda_max_replica_bound` | SOC2-CC7.2 | High | 15 | Soft risk | Off |
| 42 | `keda_trigger_auth_secrets` | CIS-5.4.1, SOC2-CC6.1 | Critical | 25 | Hard block | Soft risk |
| 43 | `keda_cooldown_period` | — | Medium | 10 | Soft risk | Off |
| 44 | `keda_polling_interval` | — | Medium | 10 | Soft risk | Off |
| 45 | `keda_fallback_replica_range` | — | Medium | 10 | Soft risk | Off |
| 46 | `keda_restore_replicas_warning` | — | Medium | 10 | Soft risk | Off |
| 47 | `keda_inline_secret_detection` | SOC2-CC6.1 | High | 20 | Soft risk | Soft risk |
| 48 | `keda_initial_cooldown` | — | Medium | 10 | Soft risk | Off |
| 49 | `keda_job_history_limits` | — | Medium | 10 | Soft risk | Off |
| 50 | `keda_paused_annotation` | — | Medium | 10 | Soft risk | Off |

### Argo CD Checks

8 checks for [Argo CD](https://argo-cd.readthedocs.io/) `Application` and `AppProject` resources.

| # | Check ID | Compliance | Severity | Points | Production | Other |
|:-:|----------|-----------|:--------:|:------:|:----------:|:-----:|
| 51 | `argocd_auto_sync_prune` | SOC2-CC7.5 | Medium | 15 | Soft risk | Off |
| 52 | `argocd_sync_retry_configured` | — | Medium | 10 | Soft risk | Off |
| 53 | `argocd_destination_not_in_cluster` | — | Medium | 15 | Soft risk | Soft risk |
| 54 | `argocd_project_not_default` | — | High | 20 | Hard block | Soft risk |
| 55 | `argocd_source_target_revision` | SLSA-L2, SOC2-CC8.1 | High | 20 | Soft risk | Off |
| 56 | `argocd_project_wildcard_destination` | CIS-5.1.1, SOC2-CC6.3 | Critical | 0 | Hard block | Hard block |
| 57 | `argocd_project_wildcard_source` | SLSA-L2, SOC2-CC8.1 | High | 20 | Soft risk | Off |
| 58 | `argocd_project_cluster_resources` | CIS-5.1.3, SOC2-CC6.3 | High | 20 | Soft risk | Off |

### Istio Checks

10 checks for [Istio](https://istio.io/) `VirtualService`, `DestinationRule`, `PeerAuthentication`, `AuthorizationPolicy`, and `Gateway` resources.

| # | Check ID | Compliance | Severity | Points | Production | Other |
|:-:|----------|-----------|:--------:|:------:|:----------:|:-----:|
| 59 | `istio_virtualservice_timeout` | SOC2-CC7.5 | Medium | 10 | Soft risk | Off |
| 60 | `istio_virtualservice_retries` | SOC2-CC7.5 | Medium | 10 | Soft risk | Off |
| 61 | `istio_virtualservice_fault_injection_production` | SOC2-CC7.2 | High | 20 | Hard block | Soft risk |
| 62 | `istio_destination_rule_tls` | CIS-5.2.1, NIST-SC-8, SOC2-CC6.7 | High | 20 | Soft risk | Off |
| 63 | `istio_destination_rule_outlier_detection` | SOC2-CC7.5 | Medium | 10 | Soft risk | Off |
| 64 | `istio_destination_rule_connection_pool` | SOC2-CC7.2 | Medium | 10 | Soft risk | Off |
| 65 | `istio_peer_auth_strict_mtls` | CIS-5.2.2, NIST-SC-8, SOC2-CC6.7 | Critical | 25 | Hard block | Soft risk |
| 66 | `istio_authz_no_allow_all` | CIS-5.2.4, NIST-AC-3, SOC2-CC6.1 | Critical | 25 | Hard block | Soft risk |
| 67 | `istio_gateway_tls_required` | CIS-5.2.3, NIST-SC-8, SOC2-CC6.7 | High | 20 | Soft risk | Off |
| 68 | `istio_gateway_wildcard_host` | SOC2-CC6.6 | Medium | 15 | Soft risk | Off |

### cert-manager Checks

6 checks for [cert-manager](https://cert-manager.io/) `Certificate`, `Issuer`, and `ClusterIssuer` resources.

| # | Check ID | Compliance | Severity | Points | Production | Other |
|:-:|----------|-----------|:--------:|:------:|:----------:|:-----:|
| 69 | `certmgr_certificate_duration` | SOC2-CC7.2 | Medium | 10 | Soft risk | Soft risk |
| 70 | `certmgr_certificate_renew_before` | SOC2-CC7.2 | Medium | 10 | Soft risk | Soft risk |
| 71 | `certmgr_certificate_private_key_algorithm` | CIS-5.4.1, SOC2-CC6.1 | High | 20 | Soft risk | Soft risk |
| 72 | `certmgr_certificate_wildcard_production` | SOC2-CC6.1 | Medium | 15 | Soft risk | Off |
| 73 | `certmgr_issuer_solver_configured` | SOC2-CC7.2 | High | 20 | Hard block | Soft risk |
| 74 | `certmgr_issuer_staging_in_production` | SOC2-CC6.1 | High | 20 | Hard block | Soft risk |

### External Secrets Operator Checks

5 checks for [External Secrets Operator](https://external-secrets.io/) `ExternalSecret`, `SecretStore`, and `ClusterSecretStore` resources.

| # | Check ID | Compliance | Severity | Points | Production | Other |
|:-:|----------|-----------|:--------:|:------:|:----------:|:-----:|
| 75 | `eso_external_secret_refresh_interval` | SOC2-CC7.2 | Medium | 10 | Soft risk | Soft risk |
| 76 | `eso_external_secret_target_creation` | SOC2-CC7.2 | Medium | 10 | Soft risk | Soft risk |
| 77 | `eso_external_secret_deletion_policy` | SOC2-CC7.2 | Medium | 10 | Soft risk | Soft risk |
| 78 | `eso_secret_store_provider` | CIS-5.4.1, SOC2-CC6.1 | High | 20 | Hard block | Soft risk |
| 79 | `eso_cluster_secret_store_conditions` | SOC2-CC6.1 | Medium | 15 | Soft risk | Soft risk |

---

## Security Scan

The security scan is a dedicated layer that goes beyond policy checks. It includes secrets detection, five extended security checks (#18-22), and a letter grade.

Enable it with `vlamguard security-scan` or leave it on by default in `vlamguard check` (disable with `--no-security-scan`).

### Secrets Detection

VlamGuard scans five surfaces for leaked credentials:
- **Container env vars and command/args**
- **ConfigMap data** (including base64-encoded values)
- **`envFrom configMapRef` cross-references** — traces ConfigMap data injected as env vars back to the referencing workload
- **Resource annotations**
- **Helm `values.yaml`** (recursively flattened)

#### Hard Patterns (deterministic regex — critical severity)

| Pattern | What it matches | Example |
|---------|----------------|---------|
| `private_key` | PEM private key headers | `-----BEGIN RSA PRIVATE KEY-----` |
| `aws_access_key` | AWS access key IDs | `AKIAIOSFODNN7EXAMPLE` |
| `github_token` | GitHub PATs and tokens | `ghp_abc123...`, `github_pat_...` |
| `database_url` | Connection strings with embedded credentials | `postgresql://user:pass@host/db` |
| `generic_password_env` | `PASSWORD=`, `SECRET=`, `TOKEN=`, `API_KEY=` with a value | `DB_PASSWORD=hunter2` |
| `aws_secret_key` | AWS secret access key (40-char base64 paired with key name) | `AWS_SECRET_ACCESS_KEY=wJalrXUt...` |

> In **production**, hard pattern matches become **hard blocks** (confirmed secrets, score=100).
> In **dev/staging**, they are downgraded to **soft risks** with high severity (+30 risk points each).

#### Soft Patterns (heuristic — medium severity)

| Pattern | What it matches |
|---------|----------------|
| `suspicious_key_name` | Key names containing `api_key`, `api-key`, `auth_token`, `auth-token`, `secret_key`, `secret-key` |
| `high_entropy_string` | Any value >= 8 characters with Shannon entropy > 4.5 bits |
| `base64_in_configmap` | Base64-encoded values (>= 20 chars) in ConfigMap data that decode successfully |

The entropy threshold of 4.5 bits is calibrated to catch random tokens and secrets while avoiding false positives from legitimate configuration values.

### Extended Security Checks

These five checks (#18-22) run as part of the security scan and focus on container isolation and network exposure:

#### `host_namespace` — Host Namespace Sharing

**Fails when:** `hostNetwork`, `hostPID`, or `hostIPC` is `true` in the pod spec.

**Why:** Host namespace sharing breaks container isolation at the kernel level. `hostPID` allows process signal attacks on the host. `hostNetwork` bypasses network policies.

#### `dangerous_volume_mounts` — Dangerous Volume Mounts

**Fails when:** A `hostPath` volume mounts any of: `/var/run/docker.sock`, `/proc`, `/sys`, `/etc`.

**Why:** Docker socket gives full daemon control. `/proc` and `/sys` expose kernel internals. `/etc` exposes host credentials.

#### `excessive_capabilities` — Excessive Linux Capabilities

**Fails when:** `securityContext.capabilities.add` includes `SYS_ADMIN`, `NET_ADMIN`, or `ALL`.

**Why:** `SYS_ADMIN` is near-equivalent to root. `ALL` grants every capability. `NET_ADMIN` enables ARP spoofing and network interception.

#### `service_account_token` — Service Account Token Auto-Mount

**Fails when:** `automountServiceAccountToken` is not explicitly `false`.

**Why:** Kubernetes mounts a service account token into every pod by default. If the app doesn't call the Kubernetes API, this is unnecessary attack surface.

#### `exposed_services` — Exposed Services

**Fails when:** Service type is `NodePort` or `LoadBalancer`.

**Why:** Both types expose services outside the cluster without the protection of an ingress controller. A LoadBalancer without proper auth is a direct attack surface.

### Security Grading (A-F)

The security grade is a deterministic F-to-A cascade — the first matching condition wins:

| Grade | Condition |
|:-----:|-----------|
| **F** | Confirmed secret in production, OR both `host_namespace` AND `dangerous_volume_mounts` fail |
| **D** | Confirmed secret in non-prod, OR 2+ extended checks fail, OR `SYS_ADMIN`/`ALL` capability detected |
| **C** | All hard-block extended checks pass BUT 3+ high-impact AI hardening recommendations, OR any single extended check still fails |
| **B** | 1-2 high-impact AI hardening recommendations, secrets clean |
| **A** | All extended checks pass, no secrets, zero high-impact recommendations |

---

## Waiver Workflow

VlamGuard supports a waiver system that allows downgrading hard blocks to soft risks with an audit trail. Useful for known issues, migration periods, or approved exceptions.

### Waiver File Format

Create a YAML file with waiver entries:

```yaml
waivers:
  - check_id: image_tag
    resource_name: legacy-app
    reason: "Legacy app uses custom tag scheme, migration planned for Q2"
    approved_by: "security-team"
    expires: "2026-06-01"

  - check_id: security_context
    resource_name: debug-tools
    reason: "Debug container needs privileged access in staging"
    approved_by: "platform-lead"
```

### Usage

```bash
# Apply waivers during analysis
vlamguard check --chart ./my-chart --waivers ./waivers.yaml --skip-ai

# Waivers also work with security-scan
vlamguard security-scan --chart ./my-chart --waivers ./waivers.yaml
```

### How It Works

- Waivers match by `check_id` and optionally `resource_name`
- A waived hard block becomes a **soft risk** instead
- Waived checks appear in the report with their waiver reason
- The `waivers_applied` field in JSON output lists all active waivers

---

## Compliance Mapping

Every policy check is tagged with compliance framework references. VlamGuard maps checks to:

- **CIS Kubernetes Benchmark** — Center for Internet Security controls
- **NSA Kubernetes Hardening Guide** — National Security Agency recommendations
- **SOC 2** — Service Organization Control trust services criteria

### CLI

```bash
# View all checks with compliance tags
vlamguard compliance

# Filter by framework
vlamguard compliance --framework CIS
vlamguard compliance --framework NSA
vlamguard compliance --framework SOC2

# JSON output for tooling
vlamguard compliance --output json
```

---

## External Tools

VlamGuard integrates with three established Kubernetes validation tools. Each runs as a subprocess; when a tool is not installed, VlamGuard silently skips it.

| Tool | Purpose | How VlamGuard uses it |
|------|---------|----------------------|
| [kube-score](https://github.com/zegl/kube-score) | Broad static analysis | Feeds manifests via stdin, maps severity grades |
| [KubeLinter](https://github.com/stackrox/kube-linter) | Security-focused checks | Writes manifests to temp dir, lints with JSON output |
| [Polaris](https://github.com/FairwindsOps/polaris) | Score-based compliance | Runs audit, returns 0-100 compliance score + findings |

External tool findings appear in a dedicated section of the report. Polaris provides a compliance score shown side-by-side with VlamGuard's own risk score.

When the AI context layer is enabled, external tool findings are passed to the AI alongside VlamGuard's own policy results. This means the AI can explain and recommend fixes for issues detected by external tools (e.g. missing NetworkPolicy from kube-score, PodDisruptionBudget from Polaris) — not just VlamGuard's own checks.

```bash
# Skip external tools
vlamguard check --chart ./my-chart --skip-external
```

> **Install all three** to get the richest analysis. VlamGuard's own 79 checks always run regardless.

---

## AI Context Layer

VlamGuard can call any OpenAI-compatible API to generate natural-language analysis. The AI receives VlamGuard's policy results and, when external tools are available, their findings too (kube-score, KubeLinter, Polaris). The AI layer provides:

- **Summary** — 2-3 sentence overview of the deployment risk
- **Impact analysis** — per-resource severity breakdown
- **Recommendations** — structured actionable steps (covering both VlamGuard and external tool findings) with:
  - `action` — what to do
  - `reason` — AI explanation of *why* this recommendation matters (security/reliability risk)
  - `resource` — target Kubernetes resource (e.g. `Deployment/web`)
  - `yaml_snippet` — exact YAML change to apply
- **Rollback suggestion** — what to do if the deployment goes wrong
- **Hardening recommendations** (security scan only) — prioritized security improvements with effort estimates, resource references, and YAML hints

#### Example AI Recommendation Output

```
Recommendations:
  1. Set security context for the container. (Deployment/web)
     Running as root allows container escape attacks and host filesystem access.
     securityContext:
       runAsNonRoot: true
       allowPrivilegeEscalation: false
  2. Define resource limits. (Deployment/web)
     Without limits, a single pod can consume all node resources and starve other workloads.
     resources:
       limits:
         cpu: 500m
         memory: 512Mi
```

### Privacy & Safety

- Manifests are **never sent raw** to the AI. VlamGuard extracts minimal metadata (kind, name, namespace, resources, security context) and strips labels, annotations, and full image tags.
- Secret values are **never included** in AI requests — only the type, location, and detection method.
- AI responses are validated with both JSON Schema and Pydantic. Invalid or hallucinated output is silently discarded.
- The deterministic engine always runs. AI adds context but never overrides the policy verdict.

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `VLAM_AI_BASE_URL` | `http://localhost:11434/v1` | API base URL (Ollama default) |
| `VLAM_AI_MODEL` | `llama3.2` | Model name |
| `VLAM_AI_API_KEY` | — | Bearer token for authenticated endpoints |
| `VLAM_AI_TIMEOUT` | `120` | AI request timeout in seconds |

Works with **Ollama**, **vLLM**, **OpenAI**, or any compatible endpoint. Create a `.env` file or export the variables.

```bash
# Skip AI entirely
vlamguard check --chart ./my-chart --skip-ai
```

---

## API Reference

Start the server:

```bash
uvicorn vlamguard.main:app --reload
# Server runs on http://localhost:8000
```

### `GET /health`

Health check endpoint.

```json
{ "status": "ok" }
```

### `POST /api/v1/analyze`

Full analysis pipeline.

**Request:**

```json
{
  "chart": "./charts/my-app",
  "values": {
    "image": { "tag": "v2.1.0" },
    "replicaCount": 3
  },
  "environment": "production",
  "skip_ai": false,
  "skip_external": false,
  "security_scan": true,
  "waivers_path": "./waivers.yaml"
}
```

| Field | Type | Required | Default | Description |
|-------|------|:--------:|---------|-------------|
| `chart` | string | Yes | — | Path to Helm chart |
| `values` | object | Yes | — | Helm values |
| `environment` | string | Yes | — | `dev`, `staging`, or `production` |
| `threshold` | int / null | No | null | Custom risk threshold 0-100 |
| `skip_ai` | bool | No | false | Skip AI context |
| `skip_external` | bool | No | false | Skip external tools |
| `security_scan` | bool | No | true | Enable security scan layer |
| `waivers_path` | string / null | No | null | Path to waiver YAML file |

**Response:**

```json
{
  "risk_score": 75,
  "risk_level": "high",
  "blocked": true,
  "hard_blocks": ["image_tag", "security_context"],
  "policy_checks": [
    {
      "check_id": "image_tag",
      "name": "Image Tag Policy",
      "passed": false,
      "severity": "critical",
      "message": "Image 'nginx:latest' uses mutable tag",
      "category": "security"
    }
  ],
  "external_findings": [],
  "polaris_score": null,
  "security_grade": "D",
  "security": {
    "secrets_detection": {
      "total_suspects": 1,
      "confirmed_secrets": 1,
      "hard_blocks": [...],
      "soft_risks": []
    },
    "extended_checks": [...],
    "hardening_recommendations": [...]
  },
  "ai_context": {
    "summary": "This deployment has critical security issues...",
    "impact_analysis": [...],
    "recommendations": [
      "Pin image tag to specific version.",
      {
        "action": "Set runAsNonRoot: true",
        "reason": "Running as root allows container escape attacks.",
        "resource": "Deployment/my-app",
        "yaml_snippet": "securityContext:\n  runAsNonRoot: true"
      }
    ],
    "rollback_suggestion": "kubectl rollout undo deployment/my-app"
  },
  "metadata": {
    "environment": "production",
    "chart": "./charts/my-app"
  }
}
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VLAM_AI_BASE_URL` | `http://localhost:11434/v1` | AI endpoint URL |
| `VLAM_AI_MODEL` | `llama3.2` | AI model name |
| `VLAM_AI_API_KEY` | — | Bearer token for AI endpoint |
| `VLAM_AI_TIMEOUT` | `120` | AI request timeout in seconds |

All variables can be set via a `.env` file in the project root.

### Optional Tool Binaries

| Binary | Purpose | Install |
|--------|---------|---------|
| `helm` | Chart rendering | [helm.sh](https://helm.sh/docs/intro/install/) |
| `kube-score` | Static analysis | [github.com/zegl/kube-score](https://github.com/zegl/kube-score) |
| `kube-linter` | Security linting | [github.com/stackrox/kube-linter](https://github.com/stackrox/kube-linter) |
| `polaris` | Compliance scoring | [github.com/FairwindsOps/polaris](https://github.com/FairwindsOps/polaris) |

---

## CI/CD Integration

VlamGuard exits with code `1` when deployments are blocked, making it directly usable as a CI gate.

For CI, the **standalone binary** is the easiest option — download once, no Python setup:

```yaml
# Download binary in CI
- name: Install VlamGuard
  run: |
    curl -Lo vlamguard https://github.com/elky-bachtiar/VlamGuard/releases/latest/download/vlamguard-linux-amd64
    chmod +x vlamguard
```

Alternatively, use the Docker image (`ghcr.io/elky-bachtiar/vlamguard:latest`) which includes all external tools pre-installed.

### GitHub Actions

```yaml
- name: VlamGuard Risk Analysis
  run: |
    vlamguard check \
      --chart ./helm-chart \
      --values ./values-${{ env.DEPLOY_ENV }}.yaml \
      --env ${{ env.DEPLOY_ENV }} \
      --skip-ai \
      --output json \
      --output-file vlamguard-report.json
```

### Jenkins

```groovy
stage('VlamGuard Risk Analysis') {
    steps {
        sh '''
            vlamguard check \
                --chart ./helm-chart \
                --values ./values-${DEPLOY_ENV}.yaml \
                --env ${DEPLOY_ENV} \
                --output markdown \
                --output-file vlamguard-report.md
        '''
    }
}
```

### GitLab CI

```yaml
vlamguard-check:
  stage: test
  image: vlamguard:latest
  script:
    - vlamguard check
        --chart ./helm-chart
        --values ./values-${DEPLOY_ENV}.yaml
        --env ${DEPLOY_ENV}
        --output markdown
        --output-file vlamguard-report.md
  artifacts:
    paths:
      - vlamguard-report.md
```

---

## Deployment

### Standalone Binaries

Pre-built single-file executables are published as [GitHub Release assets](https://github.com/elky-bachtiar/VlamGuard/releases/latest) for every `v*` tag. No Python or dependencies required on the target machine.

Supported platforms: Linux amd64, macOS Intel, macOS Apple Silicon, Windows amd64.

External tools (`helm`, `kube-score`, `kube-linter`, `polaris`) are **not bundled** — install them separately if desired. VlamGuard gracefully skips absent tools.

### Docker

```bash
docker compose up --build
```

The Docker image includes Helm, kube-score, KubeLinter, and Polaris pre-installed. The API server runs on port 8000.

Published images are available from GitHub Container Registry and Docker Hub:

```bash
# GitHub Container Registry
docker pull ghcr.io/elky-bachtiar/vlamguard:v1.0.0-alpha.2
docker pull ghcr.io/elky-bachtiar/vlamguard:latest

# Docker Hub
docker pull vlamguard/vlamguard:v1.0.0-alpha.2
docker pull vlamguard/vlamguard:latest
```

### Helm (self-deploy)

Deploy VlamGuard itself into a Kubernetes cluster:

```bash
helm install vlamguard charts/vlamguard/

# With custom AI configuration
helm install vlamguard charts/vlamguard/ \
  --set ai.baseUrl="http://my-llm:8080/v1" \
  --set ai.model="gpt-4o" \
  --set ai.apiKeySecret.create=true \
  --set ai.apiKeySecret.apiKey="sk-..."
```

The chart's default Deployment passes all 79 VlamGuard policy checks with a grade A.

---

## Running the Demo

```bash
bash demo/run_demo.sh
```

Each scenario outputs both Rich terminal display and a persistent markdown report to `demo/reports/`.

Twelve scenarios:
1. **Clean deploy** — passes all checks
2. **Evident risks** — obvious violations
3. **Subtle impact** — edge cases
4. **Best-practice violations** — medium-severity issues
5. **Hardened deployment** — fully compliant
6. **Self-analysis** — VlamGuard's own Helm chart
7. **Polaris comparison** — score benchmark (requires external tools)
8. **CRD ecosystem** — KEDA, Istio, Argo CD, cert-manager, ESO validation
9. **Waiver workflow** — hard block downgrade demonstration
10. **Compliance map** — CIS/NSA/SOC2 framework listing
11. **AI-enhanced recommendations** — structured recommendations with reasons, resource references, and YAML snippets (requires AI endpoint)
12. **External tools + AI integration** — AI explains external tool findings from kube-score and Polaris (requires both external tools and AI endpoint)

---

## Running Tests

```bash
uv run pytest                 # All tests (1116)
uv run pytest --cov           # With coverage
uv run pytest tests/unit/     # Unit + integration
uv run pytest tests/e2e/      # E2E CLI tests (requires Helm)
```

---

<p align="center">
  <sub>Built for the intersection of compliance and developer experience.</sub><br/>
  <sub><a href="../LICENSE">Apache 2.0 License</a> &bull; <a href="../CHANGELOG.md">Changelog</a> &bull; <a href="../CONTRIBUTING.md">Contributing</a></sub>
</p>
