#!/usr/bin/env bash
# Smoke-test a VlamGuard standalone binary.
# Usage: bash scripts/test_binary.sh <binary-path> [fixture-yaml]
set -euo pipefail

BINARY="${1:?Usage: test_binary.sh <binary-path> [fixture-yaml]}"
FIXTURE="${2:-tests/fixtures/clean-deploy.yaml}"
PASS=0
FAIL=0

run_test() {
    local desc="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo "  PASS  $desc"
        ((PASS++))
    else
        local rc=$?
        if [ "$rc" -le 1 ]; then
            echo "  PASS  $desc (exit $rc)"
            ((PASS++))
        else
            echo "  FAIL  $desc (exit $rc)"
            ((FAIL++))
        fi
    fi
}

echo "=== VlamGuard binary smoke tests ==="
echo "Binary: $BINARY"
echo "Fixture: $FIXTURE"
echo ""

# 1. --help works and shows expected commands
echo "[1/4] Top-level --help"
HELP_OUT=$("$BINARY" --help 2>&1) || true
if echo "$HELP_OUT" | grep -qi "check" && echo "$HELP_OUT" | grep -qi "security-scan"; then
    echo "  PASS  --help lists check and security-scan"
    ((PASS++))
else
    echo "  FAIL  --help missing expected commands"
    ((FAIL++))
fi

# 2. Subcommand help
echo "[2/4] Subcommand --help"
run_test "check --help" "$BINARY" check --help
run_test "security-scan --help" "$BINARY" security-scan --help

# 3. JSON output with fixture
echo "[3/4] check --manifests (JSON output)"
JSON_OUT=$("$BINARY" check --manifests "$FIXTURE" --skip-ai --skip-external --output json 2>&1) || true
if echo "$JSON_OUT" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'risk_score' in d" 2>/dev/null; then
    echo "  PASS  JSON output contains risk_score"
    ((PASS++))
else
    echo "  FAIL  JSON output invalid or missing risk_score"
    ((FAIL++))
fi

# 4. Exit code sanity
echo "[4/4] Exit code check"
"$BINARY" check --manifests "$FIXTURE" --skip-ai --skip-external --output json >/dev/null 2>&1
rc=$?
if [ "$rc" -le 1 ]; then
    echo "  PASS  exit code $rc (0 or 1)"
    ((PASS++))
else
    echo "  FAIL  unexpected exit code $rc"
    ((FAIL++))
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] || exit 1
