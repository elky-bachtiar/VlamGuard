#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "============================================"
echo "  VlamGuard MVP Demo"
echo "============================================"
echo ""

# Resolve the vlamguard command — prefer direct invocation, fall back to uv run
if command -v vlamguard &>/dev/null; then
  VLAMGUARD="vlamguard"
else
  VLAMGUARD="uv run vlamguard"
fi

# Locate fixtures relative to the repo root (script lives in demo/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FIXTURES="${REPO_ROOT}/tests/fixtures"

# Scenario 1: Clean Deploy
echo -e "${GREEN}━━━ Scenario 1: Clean Deploy ━━━${NC}"
echo "Helm chart with correct image tags, resource limits, security context, 3 replicas."
echo "Expected: LOW risk, pipeline passes."
echo ""
${VLAMGUARD} check --manifests "${FIXTURES}/clean-deploy.yaml" --env production --skip-ai || true
echo ""

# Scenario 2: Evident Risk
echo -e "${RED}━━━ Scenario 2: Evident Risk ━━━${NC}"
echo "Image tag 'latest', privileged container, no resource limits."
echo "Expected: BLOCKED, hard block, pipeline fails."
echo ""
${VLAMGUARD} check --manifests "${FIXTURES}/evident-risk.yaml" --env production --skip-ai || true
echo ""

# Scenario 3: Subtle Impact
echo -e "${YELLOW}━━━ Scenario 3: Subtle but Impactful ━━━${NC}"
echo "Replica count from 3 to 1 in production. All other checks pass."
echo "Expected: Soft risk score 30, pipeline warns. AI explains SPOF."
echo ""
${VLAMGUARD} check --manifests "${FIXTURES}/subtle-impact.yaml" --env production --skip-ai || true
echo ""

echo "============================================"
echo "  Demo Complete"
echo "============================================"
