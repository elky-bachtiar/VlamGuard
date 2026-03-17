# GitHub Issue Draft

**Title:** [Security]: Missing securityContext on 3 production containers

**Labels:** security, policy

**Template:** Security Policy Gap (`security_vulnerability.yml`)

---

## Policy Gap Description

Running `vlamguard check` against our production deployment flagged 3 containers that are missing a `securityContext` definition entirely. Containers without an explicit `securityContext` inherit the pod-level defaults (or worse, the runtime defaults), which can result in containers running as root, with full Linux capabilities, and without a read-only root filesystem.

Affected containers were identified during a production scan. All 3 lack any container-level `securityContext` block, meaning none of the following are explicitly set:

- `runAsNonRoot`
- `readOnlyRootFilesystem`
- `allowPrivilegeEscalation`
- `capabilities.drop`

## Policy Category

security

## Suggested Severity

high

## Example Manifest

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: example-production-deployment
spec:
  replicas: 2
  selector:
    matchLabels:
      app: example
  template:
    spec:
      containers:
        - name: app
          image: ghcr.io/example/app:1.2.3
          # No securityContext defined — this should be flagged
        - name: sidecar
          image: ghcr.io/example/sidecar:0.9.1
          # No securityContext defined
        - name: log-agent
          image: ghcr.io/example/log-agent:2.0.0
          # No securityContext defined
```

## Compliance Mapping

- **CIS Kubernetes Benchmark 5.2.6** — Minimize the admission of root containers
- **CIS Kubernetes Benchmark 5.2.7** — Minimize the admission of containers with the NET_RAW capability
- **CIS Kubernetes Benchmark 5.2.9** — Minimize the admission of containers with added capabilities
- **NSA Kubernetes Hardening Guide** — Section on non-root containers and least-privilege
- **SOC2 CC6.1** — Logical and physical access controls

## Suggested Remediation

Add an explicit `securityContext` to every container in the deployment. At minimum:

```yaml
securityContext:
  runAsNonRoot: true
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
```

If specific capabilities are required, add them back individually under `capabilities.add` rather than leaving the full default set. Re-run `vlamguard check` after applying the fix to confirm all 3 containers pass.
