# Contributing to VlamGuard

Thank you for your interest in contributing. This document covers everything needed to get a working development environment, understand the codebase conventions, and submit changes that meet the project's quality bar.

---

## Table of Contents

1. [Development Setup](#development-setup)
2. [Running Tests](#running-tests)
3. [Code Style](#code-style)
4. [Adding a Policy Check](#adding-a-policy-check)
5. [Project Structure](#project-structure)
6. [Pull Request Process](#pull-request-process)
7. [Reporting Issues](#reporting-issues)

---

## Development Setup

### Prerequisites

| Tool | Minimum Version | Purpose |
|------|----------------|---------|
| Python | 3.12 | Runtime |
| [uv](https://docs.astral.sh/uv/getting-started/installation/) | latest | Package management |
| [Helm](https://helm.sh/docs/intro/install/) | 3.x | Chart rendering (required for E2E tests) |

Optional tools (gracefully skipped when absent):

- [kube-score](https://github.com/zegl/kube-score) — static analysis
- [KubeLinter](https://github.com/stackrox/kube-linter) — security-focused checks
- [Polaris](https://github.com/FairwindsOps/polaris) — score-based compliance benchmark

### Clone and install

```bash
git clone <repo-url>
cd VlamGuard
uv sync
```

`uv sync` installs all runtime and dev dependencies into an isolated virtual environment managed by uv. No manual `venv` creation is needed.

### Verify the installation

```bash
uv run vlamguard --help
uv run vlamguard check --help
uv run vlamguard security-scan --help
```

### API server (optional, for local development)

```bash
uv run uvicorn vlamguard.main:app --reload
# Server starts at http://localhost:8000
```

### Environment variables (optional)

VlamGuard runs fully without AI. To enable AI analysis, set:

```bash
export VLAM_AI_BASE_URL="http://localhost:11434/v1"   # default: Ollama
export VLAM_AI_MODEL="llama3.2"
export VLAM_AI_API_KEY=""                             # only needed for authenticated endpoints
```

---

## Running Tests

### All tests

```bash
uv run pytest
```

### With coverage

```bash
uv run pytest --cov=src/vlamguard --cov-report=term-missing
```

The project maintains **greater than 95% line coverage**. Pull requests that reduce coverage below this threshold will not be merged. Coverage is measured only over `src/vlamguard/` — test files and demo scripts are excluded.

### Subsets

```bash
# Unit and integration only (no Helm required)
uv run pytest tests/unit/ tests/integration/

# E2E CLI tests (requires Helm 3 in PATH)
uv run pytest tests/e2e/

# A single test file
uv run pytest tests/unit/test_policies.py -v

# A specific test by name
uv run pytest -k "test_check_image_tag_blocks_latest" -v
```

### Test layout

| Directory | Contents |
|-----------|----------|
| `tests/unit/` | Isolated unit tests — one file per source module |
| `tests/integration/` | FastAPI `TestClient` integration tests |
| `tests/e2e/` | End-to-end CLI tests using `subprocess` and real Helm |
| `tests/conftest.py` | Shared fixtures |

### Mocking conventions

The project uses `unittest.mock.patch` (via `pytest`'s `monkeypatch` where convenient). Key patch targets:

```python
# Mock Helm rendering in unit/integration tests
patch("vlamguard.analyze.render_chart")

# Mock AI — security scan path (returns a 3-tuple)
patch("vlamguard.analyze.get_security_ai_context")

# Mock AI — non-security path (returns AIContext | None)
patch("vlamguard.analyze.get_ai_context")
```

Do not patch at the definition site (`vlamguard.ai.context.get_ai_context`). Always patch at the import site used by `analyze.py`.

---

## Code Style

VlamGuard is idiomatic Python 3.12. There is no autoformatter enforced by CI today, but contributions must follow these conventions to pass review.

### General rules

- **Type hints on every function signature** — both parameters and return types. Use `from __future__ import annotations` for forward references.
- **Pydantic v2 models** for all data that crosses a boundary (API request/response, AI output, policy results). Never use plain `dict` as a public interface.
- **`StrEnum`** for categorical values (`RiskLevel`, `SecurityGrade`). Avoid bare string literals for values that belong to a fixed set.
- **Early returns** — validate preconditions at the top of a function and return or raise before the happy path. Avoid deeply nested `if` trees.
- **Explicit `None` checks** — use `if value is None` rather than truthiness checks for optional fields.
- **Named exceptions** — raise typed exceptions (`ValueError`, or a project-specific subclass) with descriptive messages. Never raise a bare `Exception`.
- **No `# type: ignore`** — fix the underlying type error instead.
- **Docstrings on public functions** — one line is sufficient for simple functions; use a fuller description when behavior is non-obvious.
- **Maximum ~400 lines per file** — split responsibilities into separate modules when approaching this limit.

### Import order

Standard library, then third-party, then local imports — separated by blank lines. Follow the same pattern visible in the existing source files.

### Pydantic models

```python
from pydantic import BaseModel, Field

class PolicyCheckResult(BaseModel):
    """Result of a single policy check."""

    check_id: str
    name: str
    passed: bool
    severity: str = Field(description="critical, high, or medium")
    message: str
    details: dict | None = None
```

Use `Field(description=...)` for fields that appear in API responses. Avoid `Optional[X]` — use `X | None` (Python 3.10+ union syntax).

### Error handling

```python
# Preferred — specific, actionable
raise ValueError(f"Unknown environment: {environment!r}. Expected one of: dev, staging, production")

# Acceptable for graceful degradation in optional integrations
try:
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
except FileNotFoundError:
    return []  # Tool not installed — documented graceful skip
except subprocess.TimeoutExpired:
    return []  # Tool timed out — documented graceful skip
```

Silent `except Exception: pass` blocks are not acceptable.

---

## Adding a Policy Check

Policy checks are the core of VlamGuard's deterministic engine. Each check is a plain Python function decorated with `@policy_check`, which registers it automatically in the global registry. No other wiring is needed.

### Step 1 — Understand the registry

The registry lives in `src/vlamguard/engine/registry.py`. The decorator appends a `PolicyMeta` entry to `_REGISTRY` at import time. The pipeline calls `get_all_checks()` to retrieve every registered check.

```python
# engine/registry.py (excerpt)
_REGISTRY: list[PolicyMeta] = []

def policy_check(
    *,
    check_id: str,
    name: str,
    severity: str,      # "critical" | "high" | "medium"
    category: str,      # "security" | "reliability" | "best_practice"
    risk_points: int,   # points added to soft risk score on failure (0–30 typical)
    prod_behavior: str, # "hard_block" | "soft_risk" | "off"
    other_behavior: str,# "hard_block" | "soft_risk" | "off"
) -> Callable[[CheckFn], CheckFn]:
    ...
```

### Step 2 — Choose behaviors and severity

| `prod_behavior` / `other_behavior` | Effect |
|------------------------------------|--------|
| `"hard_block"` | Sets `blocked=True` and `risk_score=100` immediately |
| `"soft_risk"` | Adds `risk_points` to the cumulative score |
| `"off"` | Check runs but result is ignored for scoring |

Severity drives display only — blocking behavior is controlled entirely by `prod_behavior` / `other_behavior`.

### Step 3 — Write the check function

Open `src/vlamguard/engine/policies.py` and add your function at the end of the file. Every check receives a single `manifest: dict` (one parsed Kubernetes resource) and returns a `PolicyCheckResult`.

```python
from vlamguard.engine.registry import policy_check
from vlamguard.models.response import PolicyCheckResult

@policy_check(
    check_id="host_pid",                 # unique snake_case identifier
    name="Host PID Namespace",           # human-readable label shown in reports
    severity="critical",
    category="security",
    risk_points=25,
    prod_behavior="hard_block",
    other_behavior="soft_risk",
)
def check_host_pid(manifest: dict) -> PolicyCheckResult:
    """Check that pods do not share the host PID namespace."""
    pod_spec = (
        manifest.get("spec", {})
        .get("template", {})
        .get("spec", {})
    )
    if pod_spec.get("hostPID") is True:
        return PolicyCheckResult(
            check_id="host_pid",
            name="Host PID Namespace",
            passed=False,
            severity="critical",
            message="Pod shares the host PID namespace (hostPID: true).",
            details={"hostPID": True},
        )
    return PolicyCheckResult(
        check_id="host_pid",
        name="Host PID Namespace",
        passed=True,
        severity="critical",
        message="Pod does not share the host PID namespace.",
    )
```

Rules:

- Return `passed=True` when the manifest is not a workload type the check applies to (skip cleanly rather than false-positive).
- The `check_id` in the decorator and in both `PolicyCheckResult` constructors must match exactly.
- `message` must be a complete sentence describing what was found — it appears verbatim in reports.
- Include `details` only when additional structured data is useful (e.g., a list of violating container names).

### Step 4 — Write colocated tests

Add tests to `tests/unit/test_policies.py` (or `test_new_policies.py` for the extended security checks). Cover the following cases:

1. Manifest that triggers the check (violation path, `passed=False`).
2. Manifest that passes the check (`passed=True`).
3. Non-workload manifest (e.g., a `Service` or `ConfigMap`) — must return `passed=True` and not raise.

```python
def test_check_host_pid_blocks_when_enabled() -> None:
    manifest = {
        "kind": "Deployment",
        "spec": {"template": {"spec": {"hostPID": True, "containers": []}}},
    }
    result = check_host_pid(manifest)
    assert result.passed is False
    assert result.check_id == "host_pid"
    assert "hostPID" in result.message


def test_check_host_pid_passes_when_absent() -> None:
    manifest = {
        "kind": "Deployment",
        "spec": {"template": {"spec": {"containers": []}}},
    }
    result = check_host_pid(manifest)
    assert result.passed is True


def test_check_host_pid_skips_non_workload() -> None:
    result = check_host_pid({"kind": "Service"})
    assert result.passed is True
```

### Step 5 — Verify

```bash
uv run pytest tests/unit/test_policies.py -v
uv run pytest --cov=src/vlamguard --cov-report=term-missing
```

The registry count in `tests/unit/test_registry.py` may assert a specific total. Update that assertion to reflect the new count.

### Step 6 — Update documentation

Add a row to the "Policy Checks" table in `README.md` using the same column format as existing entries.

---

## Project Structure

```
VlamGuard/
├── src/vlamguard/
│   ├── analyze.py          # Pipeline orchestrator — ties all stages together
│   ├── cli.py              # Typer CLI: `vlamguard check`, `vlamguard security-scan`
│   ├── main.py             # FastAPI application and route definitions
│   ├── engine/
│   │   ├── registry.py     # @policy_check decorator and _REGISTRY
│   │   ├── policies.py     # All 22 policy check implementations
│   │   ├── scoring.py      # Risk score calculation and hard-block gating
│   │   ├── grading.py      # Deterministic A–F security grade cascade
│   │   ├── secrets.py      # Regex + Shannon entropy secrets detection
│   │   ├── external.py     # Subprocess wrappers for kube-score, KubeLinter, Polaris
│   │   ├── helm.py         # Helm template rendering via subprocess
│   │   └── environment.py  # Environment-aware behavior resolution
│   ├── ai/
│   │   ├── context.py      # OpenAI-compatible API client, prompt construction
│   │   ├── filtering.py    # Metadata filtering before sending to AI
│   │   └── schemas.py      # JSON Schema definitions for AI response validation
│   ├── models/
│   │   ├── request.py      # AnalyzeRequest (API input model)
│   │   └── response.py     # All response models (PolicyCheckResult, AIContext, etc.)
│   └── report/
│       ├── generator.py    # Markdown report generation
│       └── terminal.py     # Rich terminal output rendering
├── tests/
│   ├── conftest.py         # Shared pytest fixtures
│   ├── unit/               # Unit tests (one file per source module)
│   ├── integration/        # FastAPI TestClient tests
│   └── e2e/                # CLI subprocess tests (require Helm)
├── charts/vlamguard/       # Helm chart for deploying VlamGuard itself
├── demo/
│   ├── charts/             # Sample Helm charts for demo scenarios
│   └── run_demo.sh         # Seven demo scenarios
├── ci/                     # Example CI configs (Jenkins, GitLab)
├── pyproject.toml          # Project metadata, dependencies, pytest config
└── uv.lock                 # Locked dependency graph (commit this file)
```

### Pipeline execution order

```
Input (chart path or manifests)
  -> Helm render        (engine/helm.py)
  -> 22 Policy checks   (engine/policies.py + registry.py)
  -> Secrets detection  (engine/secrets.py)
  -> Risk scoring       (engine/scoring.py)
  -> External tools     (engine/external.py)
  -> AI context         (ai/context.py)
  -> Security grade     (engine/grading.py)
  -> Report             (report/generator.py or report/terminal.py)
```

---

## Pull Request Process

### Branch naming

```
feat/<short-description>       # new feature or policy check
fix/<short-description>        # bug fix
refactor/<short-description>   # internal restructuring without behavior change
docs/<short-description>       # documentation only
test/<short-description>       # test additions or corrections
chore/<short-description>      # dependency bumps, CI, tooling
```

Use lowercase and hyphens. Keep the description under 40 characters.

### Commit messages

VlamGuard uses [Conventional Commits](https://www.conventionalcommits.org/). Every commit on a PR branch must follow this format:

```
<type>(<scope>): <imperative summary under 72 characters>

<optional body — explain why, not what>
```

Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `perf`

Scopes (examples): `engine`, `cli`, `api`, `ai`, `report`, `secrets`, `grading`, `external`, `helm`

Examples:

```
feat(engine): add host PID namespace policy check
fix(secrets): handle missing env var key in entropy scan
test(policies): add edge cases for CronJob deadline check
docs(contributing): add policy check walkthrough
chore(deps): bump pydantic to 2.11.0
```

### Required checks before opening a PR

Run these locally and ensure all pass:

```bash
# Full test suite with coverage
uv run pytest --cov=src/vlamguard --cov-report=term-missing

# Confirm no regressions in the registry count (if you added a check)
uv run pytest tests/unit/test_registry.py -v

# Confirm E2E tests pass (requires Helm)
uv run pytest tests/e2e/ -v
```

### PR description

Include the following in every PR description:

- **What changed** — one paragraph or bullet list of the changes made.
- **Why** — motivation, linked issue if applicable.
- **Testing** — which new tests were added and what scenarios they cover.
- **Coverage** — confirm coverage remains above 95% (paste the summary line from `pytest --cov`).

### Review expectations

- All CI checks must pass before a review is requested.
- At least one approval from a maintainer is required to merge.
- Squash merging is used — the PR title becomes the merge commit message, so ensure it follows the Conventional Commits format.
- Force-pushing to `main` is not permitted.

---

## Reporting Issues

### Bug reports

Open a GitHub issue with the following information:

1. **VlamGuard version** — output of `uv run vlamguard --version` (or commit SHA if running from source).
2. **Python version** — `python --version`.
3. **Command run** — the exact `vlamguard` command, with sensitive values redacted.
4. **Expected behavior** — what you expected to happen.
5. **Actual behavior** — what happened instead (include full terminal output or JSON response).
6. **Reproduction case** — a minimal manifest or Helm chart that triggers the issue, if applicable.

### Feature requests

Open a GitHub issue with the label `enhancement`. Describe:

1. **Problem statement** — what gap or limitation you are addressing.
2. **Proposed solution** — how you would like VlamGuard to behave.
3. **Alternatives considered** — other approaches you evaluated and why you ruled them out.
4. **Scope** — whether this is a new policy check, a change to the scoring model, a CLI flag, or something else.

For new policy checks specifically, include a description of the Kubernetes resource field(s) being evaluated, the desired behavior per environment (production vs. non-production), and a sample manifest demonstrating the violation.
