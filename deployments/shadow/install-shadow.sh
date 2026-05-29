#!/usr/bin/env bash
# install-shadow.sh — deploys cf-shadow in shadow validation mode
# Run as root on the production host.
# Python daemon continues running as the authoritative enforcement daemon.
set -euo pipefail

BINARY_SRC="${1:-./bin/cf-shadow}"
INSTALL_DIR="/opt/security-automation-go"
CONFIG_DIR="/etc/security-automation-go"
STATE_DIR="/var/lib/cf-sync/shadow"
SERVICE_FILE="/etc/systemd/system/cf-shadow.service"

echo "=== cf-shadow shadow mode installer ==="
echo "IMPORTANT: Python daemon will continue running. Go observes only."
echo ""

# 1. Pre-flight checks
if ! command -v cscli &>/dev/null; then
    echo "ERROR: cscli not found. Install CrowdSec first." >&2
    exit 1
fi
if [[ ! -f "${BINARY_SRC}" ]]; then
    echo "ERROR: binary not found at ${BINARY_SRC}" >&2
    echo "Build first: go build -o bin/cf-shadow ./cmd/cf-shadow/" >&2
    exit 1
fi
if systemctl is-active --quiet crowdsec-cf-sync.service 2>/dev/null; then
    echo "✓ Python daemon (crowdsec-cf-sync) is running — will coexist with shadow mode"
else
    echo "WARNING: Python daemon not detected. Shadow comparison requires Python to be running."
fi

# 2. Install binary
mkdir -p "${INSTALL_DIR}/bin"
cp "${BINARY_SRC}" "${INSTALL_DIR}/bin/cf-shadow"
chmod 750 "${INSTALL_DIR}/bin/cf-shadow"
echo "✓ Binary installed: ${INSTALL_DIR}/bin/cf-shadow"

# 3. Config directory
mkdir -p "${CONFIG_DIR}"
if [[ ! -f "${CONFIG_DIR}/cf-shadow.env" ]]; then
    cp "deployments/shadow/cf-shadow.env.example" "${CONFIG_DIR}/cf-shadow.env"
    echo "✓ Config template written to ${CONFIG_DIR}/cf-shadow.env"
    echo "  EDIT THIS FILE: add CF_API_TOKEN and CF_ZONE_ID before starting"
fi
if [[ ! -f "${CONFIG_DIR}/cf-shadow.yaml" ]]; then
    cp "deployments/shadow/cf-shadow.yaml.example" "${CONFIG_DIR}/cf-shadow.yaml"
    echo "✓ YAML config template written to ${CONFIG_DIR}/cf-shadow.yaml"
fi

# 4. State directory
mkdir -p "${STATE_DIR}"
echo "✓ Report directory: ${STATE_DIR}"

# 5. Systemd unit
cp "deployments/shadow/cf-shadow.service" "${SERVICE_FILE}"
systemctl daemon-reload
echo "✓ Systemd unit installed: ${SERVICE_FILE}"

echo ""
echo "=== Next steps ==="
echo "1. Edit ${CONFIG_DIR}/cf-shadow.env (add CF_API_TOKEN, CF_ZONE_ID)"
echo "2. systemctl enable --now cf-shadow.service"
echo "3. Check logs: journalctl -u cf-shadow -f"
echo "4. Monitor reports: watch -n 60 cat ${STATE_DIR}/SHADOW_MODE_REPORT.md"
echo ""
echo "Reports will appear in ${STATE_DIR}/ after the first cycle:"
echo "  SHADOW_MODE_REPORT.md        — per-cycle agreement metrics"
echo "  SHADOW_DRIFT_ANALYSIS.md     — drift classification + remediation"
echo "  PYTHON_GO_PARITY_REPORT.md   — feature gap cross-reference"
echo ""
echo "Success criterion: ≥99.9% average agreement over 7 consecutive days"
