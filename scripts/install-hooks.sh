#!/usr/bin/env bash
# Install the gitleaks pre-commit hook into .git/hooks/pre-commit
# Run once after cloning: bash scripts/install-hooks.sh
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOK_FILE="$REPO_ROOT/.git/hooks/pre-commit"

cat > "$HOOK_FILE" <<'HOOK'
#!/usr/bin/env bash
# pre-commit: run gitleaks on staged content
set -euo pipefail

if ! command -v gitleaks &>/dev/null; then
    echo "[pre-commit] gitleaks not found — skipping secret scan"
    echo "[pre-commit] Install: https://github.com/gitleaks/gitleaks#installing"
    exit 0
fi

echo "[pre-commit] Running gitleaks protect..."
if ! gitleaks protect --staged --config .gitleaks.toml --redact; then
    echo ""
    echo "ERROR: gitleaks found potential secrets in staged files."
    echo "Review the output above and remove secrets before committing."
    echo "If this is a false positive, add an allowlist entry to .gitleaks.toml"
    exit 1
fi

echo "[pre-commit] gitleaks: no secrets detected"
HOOK

chmod +x "$HOOK_FILE"
echo "Installed pre-commit hook at $HOOK_FILE"
echo ""
echo "To install gitleaks: https://github.com/gitleaks/gitleaks#installing"
echo "  Ubuntu/Debian: brew install gitleaks  (or download binary from GitHub releases)"
echo "  Go install:    go install github.com/zricethezav/gitleaks/v8@latest"
