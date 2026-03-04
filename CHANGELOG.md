# Changelog

All notable changes to VlamGuard are documented here. This project uses [Conventional Commits](https://www.conventionalcommits.org/).

## [1.0.0] - 2026-03-04

Initial public release.

### Features

- **22 deterministic policy checks** across security (5 critical), reliability (6 high), and best practices (6 medium), plus 5 extended security checks
- **Secrets detection engine** with regex hard patterns (private keys, AWS keys, GitHub tokens, database URLs, passwords) and soft heuristic patterns (suspicious key names, Shannon entropy > 4.5, base64 in ConfigMaps)
- **Environment-aware risk scoring** (0-100) with binary strictness model: production = hard blocks, dev/staging = soft risks
- **Security grading** (A-F) via deterministic cascade based on secrets, extended checks, and AI hardening recommendations
- **AI context layer** calling any OpenAI-compatible API (Ollama, vLLM, OpenAI) for natural-language impact analysis, recommendations, and rollback suggestions; manifests are never sent raw
- **External tool integration** with kube-score, KubeLinter, and Polaris via subprocess; graceful degradation when tools are absent
- **CLI** (`vlamguard check`, `vlamguard security-scan`) with terminal/JSON/markdown output, file output, and CI-friendly exit codes (0=pass, 1=blocked, 2=error)
- **FastAPI server** (`POST /api/v1/analyze`, `GET /health`) for programmatic access
- **Standalone binaries** for Linux (amd64), macOS (Intel + Apple Silicon), and Windows via PyInstaller, published as GitHub Release assets
- **Helm chart** for self-deploying VlamGuard into Kubernetes clusters; default deployment scores grade A
- **Docker image** with Helm, kube-score, KubeLinter, and Polaris pre-installed
- **CI/CD** pipelines: GitHub Actions for lint, test, security tests, Docker build, Helm chart packaging, and cross-platform binary builds on `v*` tags

### Documentation

- Comprehensive README with CLI reference, policy check descriptions, and CI/CD integration examples
- Full documentation in `docs/README.md` covering pipeline architecture, risk scoring, secrets detection, security grading, API reference, and deployment options
- Contributing guide with policy check walkthrough, code style conventions, and PR process
- Seven demo scenarios in `demo/run_demo.sh`

### Testing

- 346+ tests across unit, integration, and E2E suites
- 95%+ line coverage enforced in CI
- E2E tests exercise the real CLI via subprocess with Helm rendering
