# GitHub Issue Draft

**Title:** [Security]: Missing securityContext on 3 containers in production deployment

**Labels:** security, policy

---

### Policy Gap Description

Running `vlamguard check` on our production deployment revealed that 3 containers are missing a `securityContext` definition entirely. VlamGuard should flag containers without a `securityContext` as a security risk, since this means they run with default (often permissive) privileges -- no `runAsNonRoot`, no dropped capabilities, no read-only root filesystem, and no restriction on privilege escalation.

Without an explicit `securityContext`, containers may run as root, retain all Linux capabilities, and allow privilege escalation, violating the principle of least privilege.

### Policy Category

security

### Suggested Severity

high

### Example Manifest

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: production-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: production-app
  template:
    metadata:
      labels:
        app: production-app
    spec:
      containers:
        - name: web
          image: ghcr.io/example/web:latest
          ports:
            - containerPort: 8080
          # No securityContext defined
        - name: worker
          image: ghcr.io/example/worker:latest
          # No securityContext defined
        - name: sidecar
          image: ghcr.io/example/sidecar:latest
          # No securityContext defined
```

### Compliance Mapping

- **CIS Kubernetes Benchmark 5.2.6**: Minimize the admission of root containers
- **CIS Kubernetes Benchmark 5.2.7**: Minimize the admission of containers with the NET_RAW capability
- **CIS Kubernetes Benchmark 5.2.9**: Minimize the admission of containers with added capabilities
- **NSA Kubernetes Hardening Guide**: Non-root containers, least privilege
- **SOC2 CC6.1**: Logical and physical access controls

### Suggested Remediation

Add an explicit `securityContext` to every container in the pod spec. At minimum:

```yaml
securityContext:
  runAsNonRoot: true
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
```

This ensures containers run as non-root, cannot escalate privileges, use a read-only root filesystem, and drop all Linux capabilities. Adjust as needed if specific capabilities are required by the application.
