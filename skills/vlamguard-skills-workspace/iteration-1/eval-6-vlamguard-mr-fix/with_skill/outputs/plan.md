# Plan: Remediate VlamGuard Policy Failures in `charts/vlamguard` and Open a GitLab MR

## Context

- **Project**: VlamGuard (`/Users/in615bac/Documents/VlamGuard`)
- **Chart**: `charts/vlamguard` (Helm chart for VlamGuard itself)
- **Platform**: GitLab (use `glab`, not `gh`)
- **Environment**: staging
- **Skill used**: `vlamguard-mr` (GitLab MR creator with VlamGuard report)

---

## Step 1: Run VlamGuard Check (Before)

Render the chart and run all 79 policy checks with JSON output to get machine-readable results.

```bash
cd /Users/in615bac/Documents/VlamGuard
vlamguard check --chart charts/vlamguard --environment staging --output json > /tmp/vlamguard-before.json
```

This produces the "before" baseline: risk score, grade, list of failed checks, hard blocks, and AI recommendations.

### Parse the results

```bash
# Extract key metrics from JSON output
python3 -c "
import json
with open('/tmp/vlamguard-before.json') as f:
    data = json.load(f)
print(f\"Risk Score: {data['risk_score']}/100\")
print(f\"Risk Level: {data['risk_level']}\")
print(f\"Blocked: {data['blocked']}\")
print(f\"Hard Blocks: {len(data.get('hard_blocks', []))}\")
failed = [c for c in data['policy_checks'] if not c['passed']]
print(f\"Failed Checks: {len(failed)}\")
for c in failed:
    print(f\"  - {c['check_id']} ({c['severity']}): {c['message']}\")
if data.get('ai_context', {}).get('recommendations'):
    print('AI Recommendations:')
    for r in data['ai_context']['recommendations']:
        print(f\"  - {r}\")
"
```

---

## Step 2: Identify and Apply Fixes

Based on the skill's fix mapping table and the chart's current state, the following checks are the most likely to fail. Each includes the exact fix.

### Likely Failure 1: `image_tag` (critical) -- if `tag: ""` renders without a version

The Helm template uses `{{ .Values.image.tag | default .Chart.AppVersion }}`, which resolves to `1.0.0-alpha.2`. This should pass. However, if VlamGuard's helm renderer does not evaluate Helm template expressions (and instead sees the raw `tag: ""`), this would fail.

**Fix in `charts/vlamguard/values.yaml`:**
```yaml
image:
  tag: "1.0.0-alpha.2"   # was: ""
```

### Likely Failure 2: `network_policy` (medium) -- no NetworkPolicy present

With `networkPolicy.enabled: false`, no NetworkPolicy manifest is rendered. While the per-manifest check skips non-NetworkPolicy resources, AI recommendations may flag the absence of any NetworkPolicy as a soft risk.

**Fix in `charts/vlamguard/values.yaml`:**
```yaml
networkPolicy:
  enabled: true   # was: false
```

### Likely Failure 3: `image_pull_policy` (medium) -- `Always` is correct, but only in production

In staging (`other_behavior="off"`), this check is disabled. No fix needed.

### Likely Failure 4: Any checks from AI recommendations with `yaml_snippet`

Per the skill instructions:
1. Validate that the snippet applies to this chart.
2. Adapt namespaces, labels, selectors to match existing resources.
3. Add as new templates or enable via `values.yaml`.
4. Do NOT blindly copy AI snippets.

### Applying Fixes

Edit `charts/vlamguard/values.yaml` to address each confirmed failure. For example:

```bash
# Edit values.yaml -- set explicit image tag
# In values.yaml, change:
#   tag: ""
# To:
#   tag: "1.0.0-alpha.2"

# Enable NetworkPolicy
# In values.yaml, change:
#   networkPolicy:
#     enabled: false
# To:
#   networkPolicy:
#     enabled: true
```

For any additional failures reported in the JSON output, apply fixes per the skill's mapping table:

| Check ID | Fix |
|----------|-----|
| `security_context` | Add `securityContext.runAsNonRoot: true`, `runAsUser: 1000` (already present) |
| `readonly_root_fs` | Add `readOnlyRootFilesystem: true` (already present) |
| `resource_limits` | Add `resources.limits.cpu` and `resources.limits.memory` (already present) |
| `allow_privilege_escalation` | Add `allowPrivilegeEscalation: false` (already present) |
| `excessive_capabilities` | Add `capabilities.drop: ["ALL"]` (already present) |
| `liveness_readiness_probes` | Add probes (already present) |
| `replica_count` | Set `replicas >= 2` (already 2) |
| `service_account_token` | Set `automountServiceAccountToken: false` (already present) |

---

## Step 3: Re-run VlamGuard (After)

Verify all fixes resolved the failures and capture the "after" metrics.

```bash
vlamguard check --chart charts/vlamguard --environment staging --output json > /tmp/vlamguard-after.json
```

Parse and compare:

```bash
python3 -c "
import json
with open('/tmp/vlamguard-before.json') as f:
    before = json.load(f)
with open('/tmp/vlamguard-after.json') as f:
    after = json.load(f)
print(f\"Before: score={before['risk_score']}, blocked={before['blocked']}, hard_blocks={len(before.get('hard_blocks', []))}\")
print(f\"After:  score={after['risk_score']}, blocked={after['blocked']}, hard_blocks={len(after.get('hard_blocks', []))}\")
before_failed = {c['check_id'] for c in before['policy_checks'] if not c['passed']}
after_failed = {c['check_id'] for c in after['policy_checks'] if not c['passed']}
fixed = before_failed - after_failed
print(f\"Fixed checks: {fixed}\")
if after_failed:
    print(f\"Still failing: {after_failed}\")
"
```

If any checks still fail, iterate: apply additional fixes and re-run until clean (or until only non-fixable items remain).

---

## Step 4: Create Branch and Commit

```bash
git checkout -b fix/vlamguard-chart-policy-remediation

git add charts/vlamguard/values.yaml

git commit -m "fix: remediate VlamGuard policy failures in staging chart

Before: score=X, grade=Y, Z failures
After:  score=X, grade=Y, 0 failures

- Set explicit image tag to 1.0.0-alpha.2 (avoids empty-tag ambiguity)
- Enable NetworkPolicy for default-deny posture
- [any additional changes listed here]"
```

*(Replace X, Y, Z with actual values from the before/after JSON output.)*

---

## Step 5: Push Branch

```bash
git push -u origin fix/vlamguard-chart-policy-remediation
```

---

## Step 6: Open GitLab Merge Request

Use `glab mr create` (NOT `gh pr create`) with `--description` (NOT `--body`).

```bash
glab mr create --title "fix: remediate VlamGuard policy failures in staging chart" --description "$(cat <<'EOF'
## Summary
Automated remediation of VlamGuard policy check failures in the `charts/vlamguard` Helm chart for the staging environment.

## VlamGuard Report
**Before:** Risk Score: X/100, Grade: Y, Z hard blocks
**After:**  Risk Score: X/100, Grade: Y, 0 hard blocks

## Changes Made
- `charts/vlamguard/values.yaml`: Set explicit image tag (`tag: "1.0.0-alpha.2"`) instead of empty string
- `charts/vlamguard/values.yaml`: Enabled NetworkPolicy (`networkPolicy.enabled: true`) for default-deny network posture
- [any additional changes]

## Checks Addressed
| Check ID | Before | After | Fix Applied |
|----------|--------|-------|-------------|
| `image_tag` | FAIL | PASS | Set explicit tag `1.0.0-alpha.2` |
| `network_policy` | FAIL | PASS | Enabled NetworkPolicy |
| [additional rows as needed] | | | |

## Test Plan
- [x] VlamGuard check passes after fixes
- [ ] Unit tests pass (`uv run pytest`)
- [ ] Integration tests pass
- [ ] Helm template renders cleanly (`helm template charts/vlamguard`)

## Compliance Impact
Addresses CIS-5.4.1 (image tag), CIS-5.3.2/NSA-4.1 (NetworkPolicy). No regressions in SOC2 controls.

---
Generated with [VlamGuard](https://gitlab.com/elky-bachtiar/VlamGuard)
EOF
)"
```

---

## Step 7: Return MR URL

After `glab mr create` completes, it prints the MR URL. Display it to the user:

```
Merge request created: https://gitlab.com/elky-bachtiar/VlamGuard/-/merge_requests/<ID>
```

---

## Important Notes

1. **Do NOT use `gh`** -- this is a GitLab project; always use `glab`.
2. **Do NOT commit to `main`** -- always create a feature branch.
3. **Always re-run VlamGuard** after applying fixes to verify they resolved the failures.
4. **AI yaml_snippets are hints** -- validate context before applying; skip if not applicable and note in the MR description.
5. **Only fix what VlamGuard flagged** -- do not refactor unrelated code.
6. **Before/after comparison is mandatory** in the MR description.
7. **If the re-run shows all checks pass** with no failures, the chart was already clean and no MR is needed (unless the user explicitly asks for an audit-trail MR).
8. **Fix priority order**: hard blocks (critical) first, then high severity, then medium, then AI recommendations with yaml_snippet.
