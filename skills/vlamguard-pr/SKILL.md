---
name: vlamguard-pr
description: Use when creating pull requests with VlamGuard report output, applying recommended fixes to manifests, and opening PRs with before/after analysis
---

# VlamGuard PR Creator

## Overview

Runs VlamGuard analysis on Helm charts or manifests, applies recommended fixes, commits changes to a new branch, and opens a PR with the full report embedded. Bridges VlamGuard output to actionable code changes.

## When to Use

- User asks to "fix and PR" based on VlamGuard findings
- User wants to remediate policy check failures and open a PR
- User says "run vlamguard and create a PR with fixes"
- After a `vlamguard check` shows failures that need remediation

**When NOT to use:** If user only wants the report without code changes. Use `vlamguard check` directly.

## Workflow

```dot
digraph pr_flow {
  "Run VlamGuard check" -> "Parse report";
  "Parse report" -> "Any failures?";
  "Any failures?" -> "Identify fixable checks" [label="yes"];
  "Any failures?" -> "Report clean — no PR needed" [label="no"];
  "Identify fixable checks" -> "Apply fixes to manifests";
  "Apply fixes to manifests" -> "Re-run VlamGuard";
  "Re-run VlamGuard" -> "All fixed?" ;
  "All fixed?" -> "Create branch" [label="yes"];
  "All fixed?" -> "Apply fixes to manifests" [label="no — iterate"];
  "Create branch" -> "Commit changes";
  "Commit changes" -> "Push branch";
  "Push branch" -> "gh pr create with report";
  "gh pr create with report" -> "Return PR URL";
}
```

### Steps

1. **Run VlamGuard**: Execute `vlamguard check` (or `security-scan`) with `--output json` to get machine-readable results
2. **Parse findings**: Extract failed `policy_checks`, `hard_blocks`, `security` section, and `ai_context.recommendations`
3. **Identify fixes**: Map failures to concrete manifest changes:

| Check ID | Common Fix |
|----------|------------|
| `security_context` | Add `securityContext.runAsNonRoot: true`, `runAsUser: 1000` |
| `readonly_root_fs` | Add `securityContext.readOnlyRootFilesystem: true` |
| `resource_limits` | Add `resources.limits.cpu` and `resources.limits.memory` |
| `image_tag` | Replace `:latest` with specific tag |
| `allow_privilege_escalation` | Add `securityContext.allowPrivilegeEscalation: false` |
| `excessive_capabilities` | Add `securityContext.capabilities.drop: ["ALL"]` |
| `liveness_readiness_probes` | Add liveness and readiness probe definitions |
| `replica_count` | Set `replicas: >= 2` |
| `service_account_token` | Set `automountServiceAccountToken: false` |
| `host_namespace` | Set `hostNetwork: false`, `hostPID: false`, `hostIPC: false` |

For checks not in the table above, read the check's `remediation` field from the JSON output — it contains specific fix instructions. For CRD-specific checks, also see `src/vlamguard/engine/crd/<type>.py`. Common CRD fixes:

| CRD Check | Fix |
|-----------|-----|
| `keda_min_replica_production` | Set `spec.minReplicaCount: >= 1` |
| `istio_virtualservice_timeout` | Add `timeout: "30s"` to each `spec.http[]` route |
| `argocd_auto_sync_prune` | Set `spec.syncPolicy.automated.selfHeal: true` |
| `certmgr_certificate_duration` | Set `spec.duration` and `spec.renewBefore` |
| `eso_refresh_interval` | Set `spec.refreshInterval` to a non-zero value |

4. **Apply fixes**: Edit the values.yaml or manifest files directly
5. **Re-run VlamGuard**: Verify fixes resolved the failures. Compare before/after scores.
6. **Branch & commit**:
   ```bash
   git checkout -b fix/vlamguard-<short-description>
   git add <changed-files>
   git commit -m "fix: remediate VlamGuard policy failures

   Before: score=X, grade=Y, Z failures
   After:  score=X, grade=Y, Z failures"
   ```
7. **Open PR**: Use `.github/PULL_REQUEST_TEMPLATE.md` format:
   ```bash
   gh pr create --title "fix: remediate VlamGuard policy failures" --body "$(cat <<'EOF'
   ## Summary
   Automated remediation of VlamGuard policy check failures.

   ## VlamGuard Report
   **Before:** Risk Score: X/100, Grade: Y, Z hard blocks
   **After:**  Risk Score: X/100, Grade: Y, 0 hard blocks

   ## Changes Made
   <list of manifest changes>

   ## Checks Addressed
   | Check ID | Before | After | Fix Applied |
   |----------|--------|-------|-------------|
   | ... | FAIL | PASS | ... |

   ## Test Plan
   - [x] VlamGuard check passes after fixes
   - [ ] Unit tests pass
   - [ ] Integration tests pass

   ## Compliance Impact
   <CIS/NSA/SOC2 changes if applicable, or "None">

   ---
   Generated with [VlamGuard](https://github.com/elky-bachtiar/VlamGuard)
   EOF
   )"
   ```
8. **Return**: Display the PR URL

## Fix Priority

Apply fixes in this order (highest impact first):

1. **Hard blocks** (critical severity) — these block the pipeline
2. **High severity** fails — significant security risk
3. **Medium severity** fails — best practice improvements
4. **AI recommendations** with `yaml_snippet` — ready-to-apply suggestions

## Clean Report (No Failures)

When VlamGuard reports all checks pass: **do not create a PR**. Instead:
1. Report the clean status to the user: "All 79 checks pass, score X/100, grade A — no remediation needed."
2. If the user still wants a PR (e.g. for audit trail), create one with just the report in the body and no code changes.

## Handling AI yaml_snippets

AI `yaml_snippet` fields are **hints, not drop-in code**. Follow this process:

1. **Validate context**: Does the snippet make sense for this chart/manifest?
2. **Determine placement**:
   - For Helm charts: add as new templates in `charts/<name>/templates/<resource>.yaml`, or enable via `values.yaml` if the chart already supports it (e.g. `networkPolicy.enabled: true`)
   - For raw manifests: create new files or append to existing multi-doc YAML
3. **Adapt, don't copy**: Adjust namespaces, labels, selectors, and references to match existing resources
4. **Verify**: Re-run VlamGuard after applying to confirm improvement

## Common Mistakes

- **Fixing without re-running**: Always re-run VlamGuard after applying fixes to verify
- **Blind yaml_snippet application**: AI snippets are hints, not drop-in code — validate context
- **Committing to main**: Always create a feature branch
- **Missing before/after**: The PR body MUST show score comparison
- **Over-fixing**: Only fix what VlamGuard flagged. Don't refactor unrelated code.
- **Creating PR for clean report**: No failures = no PR needed (unless user explicitly asks)
