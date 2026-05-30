#!/usr/bin/env bash
# test-all.sh — run the complete test suite with coverage reporting
# Usage: ./scripts/test-all.sh [--skip-race]
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== go vet ==="
go vet ./...
echo "✓ vet passed"
echo ""

echo "=== go test ./... ==="
go test ./...
echo "✓ all tests passed"
echo ""

if [[ "${1:-}" != "--skip-race" ]]; then
  echo "=== go test -race ./... ==="
  go test -race ./...
  echo "✓ race detector clean"
  echo ""
fi

echo "=== coverage report ==="
go test ./... -coverprofile=coverage.out -covermode=atomic
go tool cover -func=coverage.out | tail -5

echo ""
echo "=== per-package summary (sorted by coverage) ==="
go tool cover -func=coverage.out \
  | grep "total:" \
  | awk '{print $3, $1}' \
  | sort -t'%' -k1 -n \
  | tail -20

echo ""
echo "=== critical path packages ==="
go tool cover -func=coverage.out | grep -E \
  "runtime/engine|runtime/coordination|crowdsec/validation|crowdsec/adapter|policy/opa|policy/engine|runtime/scheduler|storage/sqlite|runtime/recovery|config" \
  | grep "total:" | sort

echo ""
echo "Coverage report written to: coverage.out"
echo "View HTML: go tool cover -html=coverage.out -o coverage.html && open coverage.html"
