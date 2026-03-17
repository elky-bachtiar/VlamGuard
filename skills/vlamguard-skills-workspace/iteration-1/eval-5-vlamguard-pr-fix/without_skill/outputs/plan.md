# Plan: Run VlamGuard on charts/vlamguard and Fix Findings

## Step 1: Create a feature branch

```bash
git checkout -b fix/harden-vlamguard-chart
```

## Step 2: Run VlamGuard against the Helm chart

```bash
cd /Users/in615bac/Documents/VlamGuard
uv run vlamguard check --chart charts/vlamguard --environment production
```

This renders the chart with default values and runs all 79 policy checks against every rendered manifest.

## Step 3: Predicted Findings and Fixes

Based on reading all 79 policy checks and the chart templates/values, VlamGuard would flag the following issues:

### Finding 1 (CRITICAL): `image_tag` - Image Tag Policy

**Problem:** The default `values.yaml` sets `image.tag: ""`, which causes the template to fall back to `Chart.appVersion` (`1.0.0-alpha.2`). While this is a valid tag, the `image_pull_policy` check interacts here: `pullPolicy: Always` is set, which is fine. However, the test Pod at `templates/tests/test-connection.yaml` uses `busybox:1.36` which passes (has a tag, not `latest`). No violation expected here on defaults -- this check passes.

### Finding 2 (HIGH): `security_context` - Pod-level securityContext on test Pod

**Problem:** The test Pod (`templates/tests/test-connection.yaml`) has no `securityContext` at the pod level (no `runAsNonRoot`, `runAsUser`, etc.).

**Fix:** Add pod-level and container-level securityContext to the test Pod.

### Finding 3 (HIGH): `resource_limits` - No resource limits on test Pod

**Problem:** The test Pod's `wget` container has no `resources.requests` or `resources.limits`.

**Fix:** Add resource requests/limits to the test Pod container.

### Finding 4 (HIGH): `allow_privilege_escalation` - Test Pod missing allowPrivilegeEscalation: false

**Problem:** The test Pod container has no `securityContext.allowPrivilegeEscalation: false`.

**Fix:** Add container securityContext with `allowPrivilegeEscalation: false` to the test Pod.

### Finding 5 (HIGH): `drop_all_capabilities` - Test Pod missing capabilities drop

**Problem:** The test Pod's `wget` container does not set `capabilities.drop: [ALL]`.

**Fix:** Add `capabilities.drop: [ALL]` to the test Pod container securityContext.

### Finding 6 (MEDIUM): `readonly_root_fs` - Test Pod missing readOnlyRootFilesystem

**Problem:** The test Pod's container does not set `readOnlyRootFilesystem: true`.

**Fix:** Add `readOnlyRootFilesystem: true` to the test Pod container securityContext.

### Finding 7 (MEDIUM): `service_account_token` - Test Pod missing automountServiceAccountToken

**Problem:** The test Pod does not set `automountServiceAccountToken: false` in its pod spec.

**Fix:** Add `automountServiceAccountToken: false` to the test Pod spec.

### Finding 8 (MEDIUM): `liveness_readiness_probes` - Test Pod missing probes

**Problem:** The test Pod has no liveness or readiness probes. However, this is a Helm test pod (short-lived), so this finding is expected and acceptable. VlamGuard will flag it but it can be waived or ignored since test pods are ephemeral.

**Decision:** No fix needed -- Helm test pods are ephemeral and don't need probes.

### Finding 9 (MEDIUM): `image_registry_allowlist` - Test Pod uses explicit registry

**Problem:** The test Pod uses `docker.io/library/busybox:1.36` which contains a `/` so it actually passes this check. No violation.

### Finding 10 (MEDIUM): `replica_count` - Test Pod

**Problem:** Not applicable to Pods (only Deployments). No violation.

### Finding 11 (MEDIUM): `run_as_user_group` - Test Pod missing runAsUser/runAsGroup

**Problem:** The test Pod has no `runAsUser`/`runAsGroup` set.

**Fix:** Add `runAsUser: 1000` and `runAsGroup: 1000` to test Pod securityContext.

## Step 4: Apply Fixes

### Fix A: Harden `templates/tests/test-connection.yaml`

Edit `/Users/in615bac/Documents/VlamGuard/charts/vlamguard/templates/tests/test-connection.yaml`:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: "{{ include "vlamguard.fullname" . }}-test-connection"
  labels:
    {{- include "vlamguard.labels" . | nindent 4 }}
  annotations:
    "helm.sh/hook": test
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
  containers:
    - name: wget
      image: "docker.io/library/busybox:1.36"
      command: ['wget']
      args: ['--spider', '--timeout=5', '{{ include "vlamguard.fullname" . }}:{{ .Values.service.port }}/health']
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        capabilities:
          drop:
            - ALL
      resources:
        requests:
          cpu: 10m
          memory: 16Mi
        limits:
          cpu: 50m
          memory: 32Mi
  restartPolicy: Never
```

This is the only file that needs changes. The main Deployment template already has:
- Pod-level securityContext (runAsNonRoot, runAsUser, runAsGroup, fsGroup)
- Container-level securityContext (runAsNonRoot, allowPrivilegeEscalation: false, privileged: false, readOnlyRootFilesystem: true, capabilities.drop: [ALL])
- Resource requests and limits
- Liveness and readiness probes
- automountServiceAccountToken: false
- Named container port (`http`)
- Explicit registry (`ghcr.io/elky-bachtiar/vlamguard`)
- RollingUpdate strategy
- Pod anti-affinity
- The ServiceAccount template already has `automountServiceAccountToken: false`

## Step 5: Re-run VlamGuard to confirm fixes

```bash
uv run vlamguard check --chart charts/vlamguard --environment production
```

Verify that the test Pod findings are resolved. Remaining informational items (e.g., test Pod has no probes) are acceptable for ephemeral Helm test pods.

## Step 6: Run the test suite to ensure nothing breaks

```bash
uv run pytest tests/ -x -q
```

## Step 7: Stage and commit changes

```bash
git add charts/vlamguard/templates/tests/test-connection.yaml
git commit -m "$(cat <<'EOF'
fix: harden Helm test Pod to pass VlamGuard policy checks

Add securityContext, resource limits, automountServiceAccountToken,
and capabilities restrictions to the Helm test-connection Pod so it
passes all VlamGuard production-environment policy checks.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

## Step 8: Push and open PR

```bash
git push -u origin fix/harden-vlamguard-chart
```

```bash
gh pr create --title "fix: harden Helm test Pod for VlamGuard compliance" --body "$(cat <<'EOF'
## Summary
- Ran VlamGuard policy checks (`vlamguard check --chart charts/vlamguard --environment production`) against the bundled Helm chart
- The main Deployment and all other templates already pass all 79 checks
- The Helm test Pod (`templates/tests/test-connection.yaml`) was missing several security hardening fields
- Added pod-level `securityContext` (runAsNonRoot, runAsUser, runAsGroup), container-level `securityContext` (allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities.drop: [ALL]), `automountServiceAccountToken: false`, and resource requests/limits

## Changes
- `charts/vlamguard/templates/tests/test-connection.yaml`: Added full security hardening to match the same standards as the main Deployment container

## Findings resolved
| Check ID | Severity | Description |
|---|---|---|
| `security_context` | high | Pod-level securityContext missing |
| `allow_privilege_escalation` | high | allowPrivilegeEscalation not set to false |
| `drop_all_capabilities` | high | capabilities.drop: [ALL] missing |
| `resource_limits` | high | No resource requests/limits |
| `readonly_root_fs` | medium | readOnlyRootFilesystem not set |
| `service_account_token` | medium | automountServiceAccountToken not disabled |
| `run_as_user_group` | medium | runAsUser/runAsGroup not set |

## Test plan
- [ ] `uv run vlamguard check --chart charts/vlamguard --environment production` passes clean
- [ ] `uv run pytest tests/ -x -q` passes with no regressions
- [ ] `helm template charts/vlamguard` renders without errors

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

## Summary

The VlamGuard Helm chart is already well-hardened for its primary workload (Deployment). The only template that would trigger policy violations is the Helm test Pod (`test-connection.yaml`), which is missing security context, resource limits, capability restrictions, and service account token controls. The fix is a single file change that brings the test Pod up to the same security standards as the main application container.
