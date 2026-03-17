# GitHub Issue Draft

**Title:** [Bug]: `vlamguard compliance --framework SOC2` crashes with KeyError

**Labels:** bug

**Body:**

### Description

The `vlamguard compliance` command crashes with a `KeyError` when invoked with `--framework SOC2`. The command should filter and display all policy checks tagged with SOC2 compliance mappings, but instead raises an unhandled exception.

### Steps to Reproduce

1. Install VlamGuard 1.0.0-alpha.2
2. Run `vlamguard compliance --framework SOC2`
3. Observe the KeyError traceback

### Expected Behavior

The command should display a table (or JSON output) of all policy checks that have SOC2-prefixed compliance tags (e.g., `SOC2-CC7.1`, `SOC2-CC6.1`), consistent with how `--framework CIS` and `--framework NSA` work.

### Actual Behavior

The command crashes with a `KeyError`. The `compliance` command in `src/vlamguard/cli.py` (line 311-367) calls `get_all_checks()` and `get_compliance_info()` from the registry, then filters checks whose `compliance_tags` contain the framework string. The KeyError likely originates from a mismatch between the check objects returned by `get_all_checks()` and the keys in the dict returned by `get_compliance_info()`, or from an attribute access on a check object that is missing expected fields during the SOC2 filtering or table-rendering path.

### VlamGuard Version

1.0.0-alpha.2

### Command Used

vlamguard compliance

### Environment

N/A

### Relevant Logs

```shell
$ vlamguard compliance --framework SOC2
Traceback (most recent call last):
  ...
KeyError: ...
```
