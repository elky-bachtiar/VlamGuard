# Draft: Filing a KEDA Bug Report on GitLab

Since you are on GitLab, you should use the GitLab bug report template located at `.gitlab/issue_templates/bug_report.md`. Here is what the filed issue would look like, following that template:

---

**Title:** `[Bug]: KEDA checks not working properly`

**Labels:** `bug`

---

## Description

The KEDA policy checks (15 checks under categories `keda-reliability` and `keda-security`) are not working properly. These checks are defined in `src/vlamguard/engine/crd/keda.py` and cover: min replicas, fallback configuration, auth refs, HPA ownership, max replicas, trigger auth, cooldown, polling interval, inline secrets, and others.

_(Expand with the specific failure you are seeing -- e.g., false positives, checks being skipped, incorrect severity, etc.)_

## Steps to Reproduce

1. Run `vlamguard check --chart ./my-chart` against a Helm chart that contains KEDA `ScaledObject` or `TriggerAuthentication` resources.
2. Observe that KEDA-specific policy checks produce incorrect results.

_(Fill in with the exact chart and command you used.)_

## Expected Behavior

KEDA policy checks should evaluate `ScaledObject`, `ScaledJob`, and `TriggerAuthentication` manifests correctly, flagging genuine issues (e.g., missing `minReplicaCount`, missing fallback, inline secrets in triggers) and passing clean manifests.

## Actual Behavior

_(Describe what actually happened -- e.g., "All 15 KEDA checks returned `pass` even for a ScaledObject missing minReplicaCount", or "KEDA checks were skipped entirely and not included in the report.")_

## VlamGuard Version

1.0.0-alpha.2

## Command Used

`vlamguard check` (or whichever command was used)

## Environment

- OS:
- Python:
- Helm:

## Relevant Logs

```shell
# Paste output from running with --debug flag
```

---

## How to file this on GitLab

You would create the issue through the GitLab web UI or the `glab` CLI tool (GitLab's CLI, analogous to GitHub's `gh`):

### Option A: GitLab Web UI
1. Navigate to your GitLab project.
2. Go to **Issues > New Issue**.
3. Select the **bug_report** template from the "Choose a template" dropdown.
4. Fill in the sections above and submit.

### Option B: `glab` CLI
```shell
glab issue create \
  --title "[Bug]: KEDA checks not working properly" \
  --label "bug" \
  --description "$(cat <<'EOF'
## Description

The KEDA policy checks are not working properly. ...

## Steps to Reproduce

1. Run `vlamguard check --chart ./my-chart` with KEDA resources
2. ...

## Expected Behavior

KEDA checks should correctly evaluate ScaledObject/TriggerAuthentication manifests.

## Actual Behavior

...

## VlamGuard Version

1.0.0-alpha.2

## Command Used

vlamguard check

## Environment

- OS:
- Python:
- Helm:

## Relevant Logs

```shell
```
EOF
)"
```

### Important note

This project has both `.github/ISSUE_TEMPLATE/` (GitHub) and `.gitlab/issue_templates/` (GitLab) directories. Since you are on GitLab, the `.gitlab/issue_templates/bug_report.md` template is the one that applies. The `.github/` templates are for GitHub Issues and will not be used by GitLab.
