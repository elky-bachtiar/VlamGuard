# Plan: Run `vlamguard check` on the VlamGuard Chart

## What I Would Do

Run the following command from the project root:

```bash
vlamguard check charts/vlamguard/
```

This invokes the VlamGuard CLI `check` command against the Helm chart located at `charts/vlamguard/`.

## What Happens Under the Hood

1. **Helm rendering** -- The chart at `charts/vlamguard/` is rendered into raw Kubernetes manifests (using the engine's Helm renderer).
2. **Policy evaluation** -- All 79 registered policy checks run against the rendered manifests. These cover core security (privilege escalation, host PID/IPC, default namespace, etc.), Polaris-parity rules, and CRD-specific checks for KEDA, Istio, Argo CD, cert-manager, and External Secrets Operator.
3. **Scoring and grading** -- Each finding is scored, an overall risk grade is computed, and results are classified as hard-block or soft-risk.
4. **Report output** -- A Rich-formatted terminal report is printed showing the grade, individual findings, compliance tags, and any remediation guidance.

## Why I Am Not Running It

The task instructions say "Do NOT actually run vlamguard." Running the command would require the Python environment to be activated and all dependencies installed, and the user explicitly asked me not to execute it. This document records the plan instead.

## No Changes Made

No files were created, modified, or deleted in the project source. Only this response file was written.
