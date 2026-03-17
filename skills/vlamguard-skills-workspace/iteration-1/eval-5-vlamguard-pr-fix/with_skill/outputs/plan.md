# Plan: Run VlamGuard on charts/vlamguard and Fix Findings

## Step 1: Run VlamGuard Check (Before)

```bash
cd /Users/in615bac/Documents/VlamGuard
uv run vlamguard check charts/vlamguard --output json > /tmp/vlamguard-before.json
uv run vlamguard check charts/vlamguard
```

Capture the JSON output for machine-readable parsing, and the plain text output for the PR body. Record the **risk score**, **grade**, **hard blocks count**, and **list of failed checks**.

## Step 2: Parse Findings

Extract from the JSON output:
- `policy_checks` where `passed == false`
- `hard_blocks` list
- `security` section findings
- `ai_context.recommendations` with any `yaml_snippet` hints

Based on my analysis of the chart templates and VlamGuard's 79 policy checks, the chart is already well-hardened. It has:
- Explicit image registry (`ghcr.io/elky-bachtiar/vlamguard`) with appVersion tag -- passes `image_tag` and `image_registry_allowlist`
- `securityContext` with `runAsNonRoot`, `runAsUser`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, `capabilities.drop: ["ALL"]` -- passes `security_context`, `readonly_root_fs`, `allow_privilege_escalation`, `excessive_capabilities`, `pod_security_standards`
- `automountServiceAccountToken: false` -- passes `service_account_token`
- `resources.limits` and `resources.requests` -- passes `resource_limits`
- `replicaCount: 2` -- passes `replica_count`
- Liveness and readiness probes -- passes `liveness_readiness_probes`
- No `hostPID`, `hostIPC`, `hostNetwork` -- passes `host_pid`, `host_ipc`, `host_namespace`
- NetworkPolicy template (but `enabled: false` by default)

**Likely findings that VlamGuard would flag:**

| Check ID | Likely Status | Reason |
|----------|--------------|--------|
| `network_policy` | FAIL (soft_risk in prod) | NetworkPolicy is disabled by default (`networkPolicy.enabled: false`). When VlamGuard renders the chart, the NetworkPolicy manifest is not produced, so there is no NetworkPolicy in the rendered output for the Deployment to be covered by. |
| `image_tag` | Potentially FAIL | If `image.tag` is empty string and Helm is not rendering (VlamGuard sees the template literal), this could fail. However, if VlamGuard uses `helm template` to render, the tag resolves to `1.0.0-alpha.2` from `Chart.appVersion`, which passes. |

The chart is likely near-clean. The main actionable fix would be enabling NetworkPolicy by default.

## Step 3: Apply Fixes to Manifests

Based on anticipated failures, apply these changes:

### Fix 1: Enable NetworkPolicy by Default

Edit `/Users/in615bac/Documents/VlamGuard/charts/vlamguard/values.yaml`:

```bash
# Change networkPolicy.enabled from false to true
```

**Before:**
```yaml
networkPolicy:
  # -- Enable NetworkPolicy
  enabled: false
```

**After:**
```yaml
networkPolicy:
  # -- Enable NetworkPolicy
  enabled: true
```

This ensures a NetworkPolicy is rendered by default, satisfying the `network_policy` check (CIS-5.3.2, NSA-4.1, SOC2-CC6.6).

### Fix 2 (if needed based on actual output): Any additional findings

If VlamGuard flags other checks, apply fixes per the skill's fix table:

| Check ID | Fix |
|----------|-----|
| `security_context` | Add `securityContext.runAsNonRoot: true`, `runAsUser: 1000` (already present) |
| `readonly_root_fs` | Add `securityContext.readOnlyRootFilesystem: true` (already present) |
| `resource_limits` | Add `resources.limits.cpu` and `resources.limits.memory` (already present) |
| `image_tag` | Replace `:latest` with specific tag (already uses appVersion) |
| `allow_privilege_escalation` | Add `securityContext.allowPrivilegeEscalation: false` (already present) |
| `excessive_capabilities` | Add `securityContext.capabilities.drop: ["ALL"]` (already present) |

For any AI `yaml_snippet` recommendations: validate context, adapt (not copy), and verify placement per the skill instructions.

## Step 4: Re-run VlamGuard (After)

```bash
uv run vlamguard check charts/vlamguard --output json > /tmp/vlamguard-after.json
uv run vlamguard check charts/vlamguard
```

Verify:
- All previously failing checks now pass
- Risk score improved
- No new regressions introduced

Compare before/after scores. If any checks still fail, iterate: apply additional fixes and re-run until clean (or until only non-fixable items remain).

## Step 5: Create Branch and Commit

```bash
git checkout -b fix/vlamguard-chart-network-policy
git add charts/vlamguard/values.yaml
git commit -m "$(cat <<'EOF'
fix: enable NetworkPolicy by default in VlamGuard Helm chart

Before: score=X/100, grade=Y, Z failures
After:  score=X/100, grade=Y, 0 failures

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

(Adjust the commit message to reflect actual before/after scores from Steps 1 and 4. Add any other changed files to `git add` if additional fixes were applied.)

## Step 6: Push and Open PR

```bash
git push -u origin fix/vlamguard-chart-network-policy
```

```bash
gh pr create --title "fix: enable NetworkPolicy by default in VlamGuard chart" --body "$(cat <<'EOF'
## Summary
Automated remediation of VlamGuard policy check failures on `charts/vlamguard`.

- Enabled NetworkPolicy by default to satisfy network segmentation policies

## VlamGuard Report
**Before:** Risk Score: X/100, Grade: Y, Z hard blocks
**After:**  Risk Score: X/100, Grade: Y, 0 hard blocks

## Changes Made

- [x] Policy check changes
- [x] Manifest/chart changes
- [ ] Configuration changes
- [ ] Documentation updates

**File changed:** `charts/vlamguard/values.yaml`
- Set `networkPolicy.enabled: true` (was `false`) to ensure a NetworkPolicy is rendered by default, providing network segmentation for VlamGuard pods.

## Checks Addressed

| Check ID | Before | After | Fix Applied |
|----------|--------|-------|-------------|
| `network_policy` | FAIL | PASS | Enabled NetworkPolicy by default in values.yaml |

## Test Plan
- [x] VlamGuard check passes after fixes
- [ ] Unit tests pass (`uv run pytest tests/unit/`)
- [ ] Integration tests pass (`uv run pytest tests/integration/`)
- [ ] No new security regressions

## Compliance Impact
- **CIS-5.3.2**: Network segmentation now enforced by default
- **NSA-4.1**: Network policy compliance improved
- **SOC2-CC6.6**: Logical access boundary controls strengthened

---
Generated with [VlamGuard](https://github.com/elky-bachtiar/VlamGuard)
EOF
)"
```

## Step 7: Return PR URL

Print the PR URL returned by `gh pr create` so the user can review it.

## Summary of Key Decisions

1. **Fix priority**: Following the skill's fix priority order -- hard blocks first, then high severity, then medium. The `network_policy` check is medium severity / soft_risk, but it is likely the only failing check since the chart is already well-hardened.

2. **No over-fixing**: Per the skill's "Common Mistakes" section, only fix what VlamGuard actually flags. The chart already has comprehensive security context, resource limits, probes, replicas, and service account settings.

3. **Before/after comparison**: The PR body includes score comparison as required by the skill.

4. **Branch naming**: Uses the `fix/vlamguard-<short-description>` pattern from the skill.

5. **AI yaml_snippets**: If VlamGuard's AI returns yaml_snippet recommendations, they would be validated for context and adapted (not blindly copied) before applying, per the skill's "Handling AI yaml_snippets" section.

6. **Clean report handling**: If VlamGuard reports zero failures, no PR would be created -- instead report: "All 79 checks pass, score X/100, grade A -- no remediation needed."
