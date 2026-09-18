#!/usr/bin/env bash
# Run every test module and report a single result.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

started=$(date +%s)
passed=0
failed=0

for module in tests/test_*.py; do
    name=$(basename "$module")
    output=$(python3 "$module" 2>&1)
    if [ $? -eq 0 ]; then
        count=$(echo "$output" | sed -n 's/^Ran \([0-9]\+\) tests.*/\1/p')
        echo "ok   $name (${count:-?} tests)"
        passed=$((passed + 1))
    else
        echo "FAIL $name"
        echo "$output" | tail -25 | sed 's/^/     /'
        failed=$((failed + 1))
    fi
done

echo
if [ "$failed" -eq 0 ]; then
    echo "$passed module(s) passed in $(( $(date +%s) - started ))s"
    exit 0
fi
echo "$failed module(s) failed"
exit 1
