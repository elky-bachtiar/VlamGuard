# GitLab Issue Draft

**Title:** [Bug]: istio_virtualservice_timeout false positive on routes with timeout already set

**Labels:** bug

---

## Description

The `istio_virtualservice_timeout` policy check is producing false positives. It flags VirtualService HTTP routes that already have an explicit timeout configured (e.g. `timeout: 30s`), even though those routes should pass the check. The check logic in `src/vlamguard/engine/crd/istio.py` uses `route.get("timeout")` to detect missing timeouts, but this appears to incorrectly report routes with a valid timeout as non-compliant.

## Steps to Reproduce

1. Create an Istio VirtualService manifest with an HTTP route that has `timeout: 30s` set.
2. Run `vlamguard check` against the manifest.
3. Observe that the `istio_virtualservice_timeout` check reports a failure for the route, despite the timeout being present.

## Expected Behavior

Routes with an explicit `timeout` value (e.g. `30s`) should pass the `istio_virtualservice_timeout` check without any findings.

## Actual Behavior

The check flags routes that already have a `timeout: 30s` configured, producing a false positive `soft_risk` finding indicating no timeout is set.

## VlamGuard Version

1.0.0-alpha.2

## Command Used

vlamguard check

## Environment

- OS: Not provided -- please fill in
- Python: Not provided -- please fill in
- Helm: Not provided -- please fill in

## Relevant Logs

```shell
Not provided -- please fill in. Reproduce with --debug flag and paste output here.
```
