# GitLab Issue Draft

**Title:** [Feature]: Add Crossplane CRD policy checks

**Labels:** enhancement

**Body:**

## Problem Statement

VlamGuard currently supports CRD-specific policy checks for KEDA, Istio, Argo CD, cert-manager, and External Secrets Operator, but has no coverage for Crossplane CRDs. Teams using Crossplane for infrastructure provisioning and composition have no way to validate their Crossplane manifests against best practices or catch common misconfigurations through VlamGuard's policy engine.

## Proposed Solution

Add a new set of Crossplane-specific policy checks in `src/vlamguard/engine/crd/crossplane.py`, following the existing CRD check pattern (`@policy_check` decorator with kind-filtering). Suggested checks include:

- **Composition validation**: Ensure Compositions reference valid composite resource definitions, have non-empty resource lists, and use explicit patch types.
- **Provider config checks**: Validate that ProviderConfigs exist and use secure credential sources (e.g., Secret refs rather than inline credentials).
- **CompositeResourceDefinition (XRD) checks**: Verify that XRDs define `claimNames`, specify version schemas, and set a default composition reference.
- **Managed resource checks**: Ensure managed resources reference a valid `providerConfigRef`, avoid inline credentials, and have `deletionPolicy` explicitly set.
- **Composition revision policy**: Warn when compositions lack revision pinning or when `compositionUpdatePolicy` is set to `Automatic` in production environments.

New categories would follow the existing naming convention: `crossplane-reliability` and `crossplane-security`.

## Area

CRD Support (KEDA, Istio, Argo CD, cert-manager, ESO)

## Priority

Important

## Alternatives Considered

- Using Crossplane's built-in composition validation webhooks alone, but these only cover schema-level validation and do not enforce security or reliability best practices.
- Writing standalone OPA/Rego policies for Crossplane resources, but this would live outside VlamGuard and miss the integrated scoring, grading, AI analysis, and compliance-mapping benefits.

## Additional Context

Crossplane is widely adopted for infrastructure-as-code on Kubernetes. Adding support would extend VlamGuard's CRD coverage to six ecosystems and align with the project's pattern of CRD-specific policy modules. The implementation should follow the same structure as existing CRD checks (e.g., `keda.py`, `istio.py`) and include compliance tag mapping where applicable.
