# GitHub Issue Draft

**Title:** [Bug]: `vlamguard compliance --framework SOC2` crashes with KeyError

**Labels:** bug

**Body:**

## Description

Running `vlamguard compliance --framework SOC2` raises an unhandled `KeyError`, crashing the CLI instead of displaying the filtered compliance map.

The `compliance` command in `src/vlamguard/cli.py` (lines 311-368) filters registered policy checks by framework tag and then renders them in a table or JSON output. When `--framework SOC2` is passed, the filtering step at line 322-325 iterates over `c.compliance_tags` for each `PolicyMeta` object. A `KeyError` is raised during this process, likely because a check registered in `_REGISTRY` either has an unexpected `compliance_tags` value or because the downstream `compliance_info` dictionary lookup at line 330 encounters a `check_id` that does not match any entry returned by `get_compliance_info()`.

Relevant code path:
- `src/vlamguard/cli.py` lines 311-368 (`compliance` command)
- `src/vlamguard/engine/registry.py` lines 77-79 (`get_all_checks`) and 97-107 (`get_compliance_info`)

## Steps to Reproduce

1. Install VlamGuard 1.0.0-alpha.2
2. Run:
   ```
   vlamguard compliance --framework SOC2
   ```
3. Observe `KeyError` traceback

## Expected Behavior

The command should display a table (or JSON, if `--output json` is used) of all policy checks that have a `SOC2-*` compliance tag, without raising an exception. CIS and NSA framework filters work correctly.

## Actual Behavior

The command crashes with an unhandled `KeyError`. No compliance table is shown.

## VlamGuard Version

1.0.0-alpha.2

## Command Used

vlamguard compliance

## Environment

- Python: 3.12
- OS: macOS / Linux

## Relevant Logs

```
$ vlamguard compliance --framework SOC2
Traceback (most recent call last):
  ...
KeyError: ...
```

(Full traceback to be attached once reproduced with `--debug`.)
