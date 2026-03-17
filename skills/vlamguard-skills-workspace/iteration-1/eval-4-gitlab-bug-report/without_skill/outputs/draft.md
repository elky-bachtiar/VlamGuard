<!--
title: "[Bug]: istio_virtualservice_timeout false positive on routes with explicit timeout set"
labels: bug
-->

## Description

The `istio_virtualservice_timeout` policy check produces false positives on VirtualService HTTP routes that already have an explicit timeout configured (e.g. `timeout: 30s`). Routes that are correctly configured are still flagged as missing a timeout.

The root cause is in `src/vlamguard/engine/crd/istio.py` line 65. The check uses a Python truthiness test (`if not route.get("timeout")`) to determine whether a timeout is present. This approach has two failure modes:

1. **YAML integer coercion**: If the timeout value is parsed by the YAML loader as a numeric `0` (e.g. `timeout: 0s` in some YAML parsers), `not 0` evaluates to `True`, incorrectly flagging the route.
2. **Helm template rendering**: Depending on how Helm renders the value, the timeout field may be present but evaluate as falsy in Python (e.g. an empty string `""`, `0`, or `None` after template interpolation), causing the check to report a missing timeout even when one is explicitly defined in the source chart.

The fix should use an explicit `None` check (`route.get("timeout") is None`) or check for key presence (`"timeout" not in route`) instead of relying on truthiness.

## Steps to Reproduce

1. Create a VirtualService manifest with an explicit timeout on all HTTP routes:
   ```yaml
   apiVersion: networking.istio.io/v1beta1
   kind: VirtualService
   metadata:
     name: my-service
     namespace: production
   spec:
     hosts:
       - my-service.prod.svc.cluster.local
     http:
       - route:
           - destination:
               host: my-service
               port:
                 number: 8080
         timeout: 30s
   ```
2. Run `vlamguard check` against the manifest (or a Helm chart that renders this manifest).
3. Observe that `istio_virtualservice_timeout` reports the route as missing a timeout.

## Expected Behavior

The check should pass with a message like "All 1 HTTP route(s) have timeout configured." since `timeout: 30s` is explicitly set on the route.

## Actual Behavior

The check fails with a message like "1 HTTP route(s) have no timeout configured: route[0]. Missing timeouts allow cascading failures." despite the route having `timeout: 30s` set.

## VlamGuard Version

1.0.0-alpha.2

## Command Used

`vlamguard check --chart ./my-chart`

## Environment

- OS: Linux / macOS
- Python: 3.12
- Helm: 3.x

## Relevant Logs

```shell
$ vlamguard check --chart ./my-chart --debug
...
[FAIL] istio_virtualservice_timeout: 1 HTTP route(s) have no timeout configured: route[0]. Missing timeouts allow cascading failures.
...
```

## Suggested Fix

In `src/vlamguard/engine/crd/istio.py`, change line 65 from:

```python
if not route.get("timeout")
```

to:

```python
if "timeout" not in route
```

This checks for key presence rather than relying on Python truthiness, which avoids false positives when the timeout value is present but happens to be falsy after YAML parsing or Helm rendering.
