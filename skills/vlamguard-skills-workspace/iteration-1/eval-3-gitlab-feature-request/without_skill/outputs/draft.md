---
title: "[Feature]: Crossplane CRD policy checks (Composition, Provider, XRD validation)"
labels: enhancement
---

## Problem Statement

VlamGuard currently supports CRD-specific policy checks for KEDA, Istio, Argo CD, cert-manager, and External Secrets Operator, but has no coverage for Crossplane resources. Crossplane is increasingly used to provision and manage cloud infrastructure via Kubernetes CRDs, and misconfigurations in Compositions, ProviderConfigs, or CompositeResourceDefinitions (XRDs) can lead to infrastructure drift, security gaps, or outages. Teams adopting Crossplane alongside the other supported CRDs currently have a blind spot in their change-risk analysis.

## Proposed Solution

Add a new CRD policy module at `src/vlamguard/engine/crd/crossplane.py` following the established `@policy_check` pattern, covering the following Crossplane resource kinds:

### Composition Validation (kind: `Composition`)
- **crossplane_composition_readiness_checks** — Ensure Compositions define at least one readiness check so composite resources properly report status.
- **crossplane_composition_patch_type** — Flag `PatchSet` references that don't exist or Compositions with no patches (likely misconfiguration).
- **crossplane_composition_resource_name** — Require all composed resources have an explicit `name` to prevent ordering-dependent drift.
- **crossplane_composition_function_runner** — When using Composition Functions, validate that function references are pinned to a specific version/digest rather than `latest`.

### ProviderConfig Checks (kinds: `ProviderConfig`, `Provider`)
- **crossplane_provider_config_no_inline_credentials** — Detect inline credentials in ProviderConfig `spec.credentials.source` (should use `Secret` or IRSA/Workload Identity, never `InjectedIdentity` with embedded creds).
- **crossplane_provider_pinned_version** — Ensure `Provider` resources reference a pinned package version (not `latest` or floating tag).
- **crossplane_provider_config_reference** — Verify managed resources reference a named ProviderConfig rather than relying on the implicit `default`.

### CompositeResourceDefinition / XRD Checks (kind: `CompositeResourceDefinition`)
- **crossplane_xrd_openapi_validation** — XRDs should include OpenAPI validation schema to prevent invalid claims.
- **crossplane_xrd_default_composition_ref** — Warn when no `defaultCompositionRef` is set and multiple Compositions match, risking non-deterministic selection.
- **crossplane_xrd_claim_names** — Ensure `claimNames` are set when namespace-scoped access is intended.

### Managed Resource Checks (kinds: various managed resources)
- **crossplane_managed_deletion_policy** — Flag managed resources using `deletionPolicy: Orphan` in production (risk of orphaned cloud resources on delete).
- **crossplane_managed_provider_config_ref** — Ensure managed resources explicitly set `providerConfigRef` rather than relying on defaults.

### Suggested Categories and Compliance Tags
- Categories: `crossplane-reliability`, `crossplane-security`
- Compliance tags where applicable: `SOC2-CC6.1` (credential management), `SOC2-CC7.5` (change management), `CIS` (supply chain for pinned versions)

## Area

CRD Support (Crossplane)

## Priority

Important

## Alternatives Considered

- **External tooling**: Crossplane has `crossplane beta validate`, but it only covers schema validation, not security/reliability policy enforcement. It does not integrate into VlamGuard's scoring pipeline, AI analysis, or compliance reporting.
- **OPA/Gatekeeper policies**: Could cover some of these checks, but would require a separate policy language and enforcement layer. Integrating natively into VlamGuard keeps the single-pane-of-glass experience and enables risk scoring, waivers, and compliance mapping out of the box.
- **Manual review**: Not scalable, and misses the deterministic compliance guarantees VlamGuard provides.

## Additional Context

- Crossplane resource kinds to target: `Composition`, `CompositeResourceDefinition`, `Provider`, `ProviderConfig`, and common managed resources (can be detected via `apiVersion` prefix `*.crossplane.io` or `*.upbound.io`).
- The implementation should follow the same pattern as existing CRD modules (e.g., `keda.py`, `istio.py`): kind-filtering with early `passed=True` skip for non-matching kinds, `@policy_check` decorator with severity/category/compliance metadata, and corresponding test file (`test_crossplane_policies.py`).
- Estimated scope: ~12 policy checks, consistent with the 5-15 range of existing CRD modules.
- The `test_categories_valid` test will need updating to allow `crossplane-reliability` and `crossplane-security` categories.
