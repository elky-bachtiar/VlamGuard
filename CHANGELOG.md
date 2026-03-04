# Changelog

All notable changes to VlamGuard are documented here. This project uses [Conventional Commits](https://www.conventionalcommits.org/).

## [1.0.0-alpha.1] - 2026-03-04

Enterprise readiness alpha release.

### Features

#### AI-Integrated External Tool Findings

- External tool findings (kube-score, KubeLinter, Polaris) are now passed to the AI context layer
- AI can explain and recommend fixes for issues detected by external tools (e.g. missing NetworkPolicy, ephemeral storage limits, PodDisruptionBudget, label mismatches)
- Both system prompts (`_SYSTEM_PROMPT` and `_SECURITY_SYSTEM_PROMPT`) updated to instruct the AI to cover external tool findings in its recommendations
- External findings included as `external_tool_findings` array in the AI prompt data when present
- No-op when external tools are skipped or produce no findings — fully backward compatible

#### Structured AI Recommendations

- AI recommendations are now structured objects with `action`, `reason`, `resource`, and `yaml_snippet` fields
- `reason` field provides AI explanation of *why* each recommendation matters (security/reliability risk)
- `resource` field references the target Kubernetes resource (e.g. `Deployment/web`)
- `yaml_snippet` provides the exact YAML change to apply
- Plain string recommendations remain supported for backward compatibility (mixed arrays accepted)
- Hardening recommendations (`HardeningAction`) also gained a `resource` field
- Terminal output renders reason in italic below the action, followed by dimmed YAML snippet
- Markdown output renders reason as italic text with YAML in fenced code blocks
- JSON Schema updated with `oneOf` validation for mixed recommendation arrays

#### Dual Output Mode

- `--output-file` with terminal output now writes a markdown report AND displays Rich terminal output simultaneously
- Demo script updated: all 12 scenarios save markdown reports to `demo/reports/` alongside terminal display

#### Policy Engine — 79 checks (was 22)

**Core Kubernetes checks (36)** — expanded from 22 with 14 new P0 entries:
- `allow_privilege_escalation` — blocks containers missing `allowPrivilegeEscalation: false`
- `drop_all_capabilities` — enforces `ALL` in `capabilities.drop`
- `host_pid` / `host_ipc` — blocks host PID/IPC namespace sharing
- `default_namespace` — flags workloads deployed to the `default` namespace
- `pod_security_standards` — validates `pod-security.kubernetes.io` label presence and level
- `ingress_tls` — requires TLS on all Ingress resources
- `host_port_restriction` — blocks `hostPort` usage on containers
- `rbac_wildcard_permissions` — flags `*` verbs or resources in RBAC rules
- `image_registry_allowlist` — enforces images originate from approved registries
- `container_port_name` — requires IANA-valid port names
- `automount_service_account` — requires explicit `automountServiceAccountToken: false`
- `hpa_target_ref` — validates HorizontalPodAutoscaler target reference resolution
- `resource_quota` — checks namespace-level ResourceQuota presence

**KEDA checks (14)** — new CRD ecosystem:
- ScaledObject and ScaledJob validation: target deployment/job existence, trigger authentication references, min/max replica bounds, cooldown period safety, polling interval, failed job history limit, metric server connectivity annotation

**Istio checks (10)** — new CRD ecosystem:
- VirtualService: host resolution, route weight sum, retries, timeout consistency
- DestinationRule: mTLS mode validation, circuit breaker thresholds
- PeerAuthentication: mtls mode conflicts with namespace policy
- ServiceEntry: port/protocol consistency

**Argo CD checks (8)** — new CRD ecosystem:
- Application: destination server/namespace validation, automated sync policy, self-heal flag, prune safety, health check annotations
- AppProject: source repo allowlist, destination allowlist, cluster role bindings

**cert-manager checks (6)** — new CRD ecosystem:
- Certificate: duration/renewBefore ratio, secret name uniqueness, issuer reference resolution, ACME solver config
- ClusterIssuer / Issuer: ACME server reachability annotation, private key secret reference

**External Secrets Operator checks (5)** — new CRD ecosystem:
- ExternalSecret: store reference existence, refresh interval safety, data key uniqueness
- SecretStore / ClusterSecretStore: provider credential secret reference, connection timeout annotation

#### Chart Discovery

- `vlamguard discover [ROOT]` command recursively finds all Helm charts under a directory tree and runs risk analysis on each
- Prints per-chart results followed by a summary table (chart, score, grade, status)
- JSON output wraps all results with a `summary` object (`total`, `passed`, `blocked`, `errors`)
- Graceful error handling: charts that fail to render are reported as `ERROR` without blocking other charts
- Skips `.git`, `node_modules`, `vendor`, `__pycache__`, `.venv`, and other non-project directories
- Exits `1` if any chart is blocked, `0` otherwise

#### Waiver Workflow

- `--waivers <file>` flag on `vlamguard check` accepts a YAML waiver manifest
- Waivers downgrade hard blocks to soft risks for specified check IDs, resources, and expiry dates
- Expired waivers are rejected at parse time with a clear error message
- Full audit trail: every applied waiver is recorded in the JSON/markdown report under `waivers_applied`
- Waiver schema enforced via Pydantic; malformed waiver files produce actionable validation errors

#### Compliance Mapping

- All 79 checks carry `compliance_tags` mapping to CIS Kubernetes Benchmark, NSA/CISA Hardening Guide, and SOC 2 control identifiers
- `vlamguard compliance` command lists checks grouped by framework
- `--framework <cis|nsa|soc2>` filter narrows output to checks relevant to a single framework
- Compliance summary included in JSON and markdown report output

#### Demo Scenario 12: External Tools + AI Integration

- New demo scenario showing AI-explained external tool findings
- Three sub-scenarios (evident risk, subtle impact, hardened) when both external tools and AI endpoint are available
- Graceful fallback when only external tools or only AI are available

#### Existing Features (carried forward from 1.0.0)

- Secrets detection engine: regex hard patterns + Shannon entropy + soft heuristics; environment-aware blocking
- Security grading (A-F) via deterministic cascade
- AI context layer (OpenAI-compatible): impact analysis, recommendations, rollback suggestions; manifests never sent raw
- External tool integration: kube-score, KubeLinter, Polaris with graceful degradation; findings fed to AI
- CLI (`vlamguard check`, `vlamguard security-scan`, `vlamguard discover`) with terminal/JSON/markdown output and CI-friendly exit codes
- FastAPI server (`POST /api/v1/analyze`, `GET /health`)
- Standalone binaries for Linux (amd64), macOS (Intel + Apple Silicon), Windows
- Helm chart for self-deploying VlamGuard; default deployment scores grade A
- Docker image with Helm, kube-score, KubeLinter, and Polaris pre-installed

### Documentation

- Updated README with full 79-check policy reference, waiver workflow guide, compliance command usage, `discover` command examples, structured AI recommendations example, dual output mode, and external tools + AI integration
- Extended `docs/README.md`: CRD ecosystem sections (KEDA, Istio, Argo CD, cert-manager, ESO), waiver schema reference, compliance framework mapping table, `vlamguard discover` CLI reference with JSON output schema, AI recommendation example output, updated demo section (12 scenarios), external tool findings in AI context
- Added `docs/waivers.md` with waiver YAML schema, examples, and expiry semantics
- Added `docs/compliance.md` with CIS/NSA/SOC2 control cross-reference table

### Testing

- 1116 tests across unit, integration, and E2E suites (was 346+)
- 99%+ line coverage across all source files (was 95%+ enforced floor)
- Full unit coverage for all 79 policy checks including parameterised pass/fail/edge cases
- Waiver workflow tests: valid waivers, expired waivers, malformed schemas, audit trail assertions
- Compliance command tests: framework filter output, tag presence on every registered check
- CRD ecosystem tests use fixture manifests covering valid and invalid configurations for each check

### Bug Fixes

- Fixed crash in `run_kube_score()` when kube-score returns JSON `null` for certain manifests (e.g. CRD-only inputs); added guard for `None` result after `json.loads()`
