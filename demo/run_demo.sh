#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo "============================================"
echo "  VlamGuard Demo"
echo "============================================"
echo ""

# Resolve the vlamguard command — prefer direct invocation, fall back to uv run
if command -v vlamguard &>/dev/null; then
  VLAMGUARD="vlamguard"
else
  VLAMGUARD="uv run vlamguard"
fi

# Locate directories relative to the repo root (script lives in demo/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FIXTURES="${REPO_ROOT}/tests/fixtures"
DEMO_CHARTS="${SCRIPT_DIR}/charts"

# Scenario 1: Clean Deploy (pre-rendered manifests)
echo -e "${GREEN}━━━ Scenario 1: Clean Deploy ━━━${NC}"
echo "Helm chart with correct image tags, resource limits, security context, 3 replicas."
echo "Expected: LOW risk, pipeline passes."
echo ""
${VLAMGUARD} check --manifests "${FIXTURES}/clean-deploy.yaml" --env production --skip-ai || true
echo ""

# Scenario 2: Evident Risk (pre-rendered manifests)
echo -e "${RED}━━━ Scenario 2: Evident Risk ━━━${NC}"
echo "Image tag 'latest', privileged container, no resource limits."
echo "Expected: BLOCKED, hard block, pipeline fails."
echo ""
${VLAMGUARD} check --manifests "${FIXTURES}/evident-risk.yaml" --env production --skip-ai || true
echo ""

# Scenario 3: Subtle Impact (pre-rendered manifests)
echo -e "${YELLOW}━━━ Scenario 3: Subtle but Impactful ━━━${NC}"
echo "Replica count from 3 to 1 in production. All other checks pass."
echo "Expected: Soft risk score ~30, pipeline warns. AI explains SPOF."
echo ""
${VLAMGUARD} check --manifests "${FIXTURES}/subtle-impact.yaml" --env production --skip-ai || true
echo ""

# Scenario 4: Best-Practices Failures (Helm chart)
echo -e "${RED}━━━ Scenario 4: Best-Practice Violations ━━━${NC}"
echo "Legacy app: deprecated API, NodePort, duplicate envs, no probes, no PDB."
echo "Expected: BLOCKED, 11 failing checks."
echo ""
${VLAMGUARD} check --chart "${DEMO_CHARTS}/best-practices-fail" --env production --skip-ai || true
echo ""

# Scenario 5: Hardened Deployment (Helm chart)
echo -e "${GREEN}━━━ Scenario 5: Fully Hardened ━━━${NC}"
echo "All 17 checks pass: security context, probes, PDB, NetworkPolicy, anti-affinity."
echo "Expected: PASSED, risk score 0/100."
echo ""
${VLAMGUARD} check --chart "${DEMO_CHARTS}/hardened" --env production --skip-ai || true
echo ""

# Scenario 6: VlamGuard's Own Chart (self-analysis)
if [ -d "${REPO_ROOT}/charts/vlamguard" ]; then
  echo -e "${CYAN}━━━ Scenario 6: Self-Analysis (Eat Your Own Dog Food) ━━━${NC}"
  echo "VlamGuard analyzes its own Helm chart."
  echo "Expected: PASSED, risk score 0/100."
  echo ""
  ${VLAMGUARD} check --chart "${REPO_ROOT}/charts/vlamguard" --env production --skip-ai || true
  echo ""
fi

echo "============================================"
echo "  Demo Complete"
echo "============================================"
