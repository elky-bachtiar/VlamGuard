#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
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

# Check for external tools availability
EXTERNAL_FLAGS="--skip-external"
if command -v kube-score &>/dev/null || command -v kube-linter &>/dev/null || command -v polaris &>/dev/null; then
  EXTERNAL_FLAGS=""
  echo -e "${GREEN}External tools detected — enabling kube-score/KubeLinter/Polaris integration${NC}"
else
  echo -e "${YELLOW}External tools not found — running with VlamGuard engine only${NC}"
  echo "Install kube-score, kube-linter, and/or polaris for full comparison demo."
fi
echo ""

# Locate directories relative to the repo root (script lives in demo/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FIXTURES="${REPO_ROOT}/tests/fixtures"
DEMO_CHARTS="${SCRIPT_DIR}/charts"

# Create reports directory for markdown output
REPORTS="${SCRIPT_DIR}/reports"
mkdir -p "${REPORTS}"
echo -e "${CYAN}Markdown reports will be saved to: demo/reports/${NC}"
echo ""

# Scenario 1: Clean Deploy (pre-rendered manifests)
echo -e "${GREEN}━━━ Scenario 1: Clean Deploy ━━━${NC}"
echo "Helm chart with correct image tags, resource limits, security context, 3 replicas."
echo "Expected: LOW risk, pipeline passes."
echo ""
${VLAMGUARD} check --manifests "${FIXTURES}/clean-deploy.yaml" --env production --skip-ai ${EXTERNAL_FLAGS} --output-file "${REPORTS}/01-clean-deploy.md" || true
echo ""

# Scenario 2: Evident Risk (pre-rendered manifests)
echo -e "${RED}━━━ Scenario 2: Evident Risk ━━━${NC}"
echo "Image tag 'latest', privileged container, no resource limits."
echo "Expected: BLOCKED, hard block, pipeline fails."
echo "Demo point: kube-score finds these too — but VlamGuard adds AI context."
echo ""
${VLAMGUARD} check --manifests "${FIXTURES}/evident-risk.yaml" --env production --skip-ai ${EXTERNAL_FLAGS} --output-file "${REPORTS}/02-evident-risk.md" || true
echo ""

# Scenario 3: Subtle Impact (pre-rendered manifests)
echo -e "${YELLOW}━━━ Scenario 3: Subtle but Impactful ━━━${NC}"
echo "Replica count from 3 to 1 in production. All other checks pass."
echo "Expected: Soft risk score ~30, pipeline warns. AI explains SPOF."
echo "Demo point: kube-score/KubeLinter/Polaris may not flag this — VlamGuard does."
echo ""
${VLAMGUARD} check --manifests "${FIXTURES}/subtle-impact.yaml" --env production --skip-ai ${EXTERNAL_FLAGS} --output-file "${REPORTS}/03-subtle-impact.md" || true
echo ""

# Scenario 4: Best-Practices Failures (Helm chart)
echo -e "${RED}━━━ Scenario 4: Best-Practice Violations ━━━${NC}"
echo "Legacy app: deprecated API, NodePort, duplicate envs, no probes, no PDB."
echo "Expected: BLOCKED, 11 failing checks."
echo ""
${VLAMGUARD} check --chart "${DEMO_CHARTS}/best-practices-fail" --env production --skip-ai ${EXTERNAL_FLAGS} --output-file "${REPORTS}/04-best-practices-fail.md" || true
echo ""

# Scenario 5: Hardened Deployment (Helm chart)
echo -e "${GREEN}━━━ Scenario 5: Fully Hardened ━━━${NC}"
echo "All checks pass: security context, probes, PDB, NetworkPolicy, anti-affinity."
echo "Expected: PASSED, risk score 0/100."
echo ""
${VLAMGUARD} check --chart "${DEMO_CHARTS}/hardened" --env production --skip-ai ${EXTERNAL_FLAGS} --output-file "${REPORTS}/05-hardened.md" || true
echo ""

# Scenario 6: VlamGuard's Own Chart (self-analysis)
if [ -d "${REPO_ROOT}/charts/vlamguard" ]; then
  echo -e "${CYAN}━━━ Scenario 6: Self-Analysis (Eat Your Own Dog Food) ━━━${NC}"
  echo "VlamGuard analyzes its own Helm chart."
  echo "Expected: PASSED, risk score 0/100."
  echo ""
  ${VLAMGUARD} check --chart "${REPO_ROOT}/charts/vlamguard" --env production --skip-ai ${EXTERNAL_FLAGS} --output-file "${REPORTS}/06-self-analysis.md" || true
  echo ""
fi

# Scenario 7: Polaris Score Comparison (only if external tools are available)
if [ -z "${EXTERNAL_FLAGS}" ]; then
  echo -e "${BLUE}━━━ Scenario 7: Polaris Score Comparison ━━━${NC}"
  echo "Side-by-side comparison: VlamGuard risk score vs Polaris compliance score."
  echo ""

  echo -e "${GREEN}7a. Hardened chart — both engines should approve:${NC}"
  ${VLAMGUARD} check --chart "${DEMO_CHARTS}/hardened" --env production --skip-ai --output-file "${REPORTS}/07a-polaris-hardened.md" || true
  echo ""

  echo -e "${RED}7b. Evident risk chart — compare how each tool reports issues:${NC}"
  ${VLAMGUARD} check --manifests "${FIXTURES}/evident-risk.yaml" --env production --skip-ai --output-file "${REPORTS}/07b-polaris-evident-risk.md" || true
  echo ""

  echo -e "${YELLOW}7c. Subtle impact — VlamGuard detects what Polaris may miss:${NC}"
  ${VLAMGUARD} check --manifests "${FIXTURES}/subtle-impact.yaml" --env production --skip-ai --output-file "${REPORTS}/07c-polaris-subtle-impact.md" || true
  echo ""
fi

# Scenario 8: CRD Ecosystem Checks
echo -e "${CYAN}━━━ Scenario 8: CRD Ecosystem Checks ━━━${NC}"
echo "VlamGuard validates KEDA, Istio, Argo CD, cert-manager, and ESO resources."
echo ""

echo -e "${RED}8a. KEDA violations — ScaledObject/ScaledJob/TriggerAuthentication:${NC}"
${VLAMGUARD} check --manifests "${FIXTURES}/crd-keda-violations.yaml" --env production --skip-ai ${EXTERNAL_FLAGS} --output-file "${REPORTS}/08a-crd-keda.md" || true
echo ""

echo -e "${RED}8b. Istio violations — VirtualService/DestinationRule/PeerAuth/AuthzPolicy/Gateway:${NC}"
${VLAMGUARD} check --manifests "${FIXTURES}/crd-istio-violations.yaml" --env production --skip-ai ${EXTERNAL_FLAGS} --output-file "${REPORTS}/08b-crd-istio.md" || true
echo ""

echo -e "${RED}8c. Argo CD violations — Application/AppProject:${NC}"
${VLAMGUARD} check --manifests "${FIXTURES}/crd-argocd-violations.yaml" --env production --skip-ai ${EXTERNAL_FLAGS} --output-file "${REPORTS}/08c-crd-argocd.md" || true
echo ""

echo -e "${RED}8d. cert-manager violations — Certificate/ClusterIssuer:${NC}"
${VLAMGUARD} check --manifests "${FIXTURES}/crd-certmanager-violations.yaml" --env production --skip-ai ${EXTERNAL_FLAGS} --output-file "${REPORTS}/08d-crd-certmanager.md" || true
echo ""

echo -e "${RED}8e. ESO violations — ExternalSecret/SecretStore/ClusterSecretStore:${NC}"
${VLAMGUARD} check --manifests "${FIXTURES}/crd-eso-violations.yaml" --env production --skip-ai ${EXTERNAL_FLAGS} --output-file "${REPORTS}/08e-crd-eso.md" || true
echo ""

echo -e "${GREEN}8f. CRD clean — all ecosystems, zero violations:${NC}"
${VLAMGUARD} check --manifests "${FIXTURES}/crd-clean.yaml" --env production --skip-ai ${EXTERNAL_FLAGS} --output-file "${REPORTS}/08f-crd-clean.md" || true
echo ""

# Scenario 9: Waiver Workflow
echo -e "${YELLOW}━━━ Scenario 9: Waiver Workflow ━━━${NC}"
echo "Waivers downgrade hard_block to soft_risk. They never suppress findings."
echo ""

echo -e "${RED}9a. Without waivers (baseline):${NC}"
${VLAMGUARD} check --manifests "${FIXTURES}/evident-risk.yaml" --env production --skip-ai ${EXTERNAL_FLAGS} --output json 2>/dev/null \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps({'blocked':d['blocked'],'risk_score':d['risk_score'],'hard_blocks':d['hard_blocks'],'waivers_applied':d['waivers_applied']},indent=2))" || true
echo ""

echo -e "${GREEN}9b. With waivers (image_tag + security_context waived):${NC}"
${VLAMGUARD} check --manifests "${FIXTURES}/evident-risk.yaml" --env production --skip-ai ${EXTERNAL_FLAGS} --waivers "${SCRIPT_DIR}/waivers-example.yaml" --output json 2>/dev/null \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps({'blocked':d['blocked'],'risk_score':d['risk_score'],'hard_blocks':d['hard_blocks'],'waivers_applied':d['waivers_applied']},indent=2))" || true
echo ""

# Scenario 10: Compliance Map
echo -e "${BLUE}━━━ Scenario 10: Compliance Map ━━━${NC}"
echo "Lists all policy checks with CIS/NSA/SOC2 compliance mappings."
echo ""

echo -e "${CYAN}10a. Full compliance map:${NC}"
${VLAMGUARD} compliance || true
echo ""

echo -e "${CYAN}10b. CIS Benchmark filter:${NC}"
${VLAMGUARD} compliance --framework CIS || true
echo ""

# Scenario 11: AI-Enhanced Recommendations (requires AI endpoint)
echo -e "${BLUE}━━━ Scenario 11: AI-Enhanced Recommendations ━━━${NC}"
echo "When an AI endpoint is configured (VLAM_AI_BASE_URL), VlamGuard produces"
echo "structured recommendations with resource references and YAML snippets."
echo ""
echo "Example AI recommendation output:"
echo "  1. Set runAsNonRoot: true (Deployment/web)"
echo "     securityContext:"
echo "       runAsNonRoot: true"
echo "  2. Pin image tag to specific version."
echo ""

if [ -n "${VLAM_AI_BASE_URL:-}" ]; then
  echo -e "${GREEN}AI endpoint detected (${VLAM_AI_BASE_URL}) — running with AI context:${NC}"
  echo ""
  ${VLAMGUARD} check --manifests "${FIXTURES}/evident-risk.yaml" --env production ${EXTERNAL_FLAGS} --output-file "${REPORTS}/11-ai-recommendations.md" || true
  echo ""
else
  echo -e "${YELLOW}No AI endpoint configured. Set VLAM_AI_BASE_URL to enable.${NC}"
  echo "Example: export VLAM_AI_BASE_URL=http://localhost:11434/v1"
  echo ""
  echo -e "${CYAN}Running without AI to show the terminal + markdown dual output:${NC}"
  ${VLAMGUARD} check --manifests "${FIXTURES}/evident-risk.yaml" --env production --skip-ai ${EXTERNAL_FLAGS} --output-file "${REPORTS}/11-no-ai-baseline.md" || true
  echo ""
fi

# Scenario 12: External Tools + AI Integration
echo -e "${BLUE}━━━ Scenario 12: External Tools + AI Integration ━━━${NC}"
echo "When external tools (kube-score, Polaris) and AI are both available, VlamGuard"
echo "passes external tool findings to the AI — so the AI explains and recommends fixes"
echo "for issues found by kube-score (e.g. ephemeral storage, NetworkPolicy) and Polaris"
echo "(e.g. PodDisruptionBudget, label mismatches)."
echo ""

if [ -z "${EXTERNAL_FLAGS}" ] && [ -n "${VLAM_AI_BASE_URL:-}" ]; then
  echo -e "${GREEN}Both external tools and AI detected — running full integration:${NC}"
  echo ""

  echo -e "${RED}12a. Evident risk — AI explains external tool findings:${NC}"
  echo "External tools detect issues VlamGuard doesn't check (ephemeral storage, NetworkPolicy,"
  echo "PodDisruptionBudget). The AI now receives these findings and explains them."
  echo ""
  ${VLAMGUARD} check --manifests "${FIXTURES}/evident-risk.yaml" --env production --output-file "${REPORTS}/12a-external-ai-evident-risk.md" || true
  echo ""

  echo -e "${YELLOW}12b. Subtle impact — external tools + AI on borderline manifest:${NC}"
  echo "VlamGuard flags the single replica. External tools may add more context."
  echo "AI synthesizes both VlamGuard and external findings into a unified analysis."
  echo ""
  ${VLAMGUARD} check --manifests "${FIXTURES}/subtle-impact.yaml" --env production --output-file "${REPORTS}/12b-external-ai-subtle-impact.md" || true
  echo ""

  echo -e "${GREEN}12c. Hardened chart — external tools + AI confirm clean state:${NC}"
  echo "Both engines agree: zero or minimal findings. AI confirms readiness."
  echo ""
  ${VLAMGUARD} check --chart "${DEMO_CHARTS}/hardened" --env production --output-file "${REPORTS}/12c-external-ai-hardened.md" || true
  echo ""

elif [ -z "${EXTERNAL_FLAGS}" ]; then
  echo -e "${YELLOW}External tools available but no AI endpoint configured.${NC}"
  echo "Set VLAM_AI_BASE_URL to see AI-explained external tool findings."
  echo "Example: export VLAM_AI_BASE_URL=http://localhost:11434/v1"
  echo ""
  echo "Running external tools only (no AI) for comparison:"
  echo ""
  ${VLAMGUARD} check --manifests "${FIXTURES}/evident-risk.yaml" --env production --skip-ai --output-file "${REPORTS}/12a-external-only-evident-risk.md" || true
  echo ""

elif [ -n "${VLAM_AI_BASE_URL:-}" ]; then
  echo -e "${YELLOW}AI endpoint configured but no external tools found.${NC}"
  echo "Install kube-score, polaris, or kube-linter to see external findings in AI analysis."
  echo "  brew install kube-score polaris"
  echo ""

else
  echo -e "${YELLOW}Neither external tools nor AI endpoint available.${NC}"
  echo "For the full demo, install external tools and configure an AI endpoint:"
  echo "  brew install kube-score polaris"
  echo "  export VLAM_AI_BASE_URL=http://localhost:11434/v1"
  echo ""
fi

echo "============================================"
echo -e "  Demo Complete — Reports saved to ${CYAN}demo/reports/${NC}"
echo "============================================"
