#!/usr/bin/env bash
#
# SilentGuard XDR — Linux agent installer.
#
# Installs the agent as a systemd service running as root, so enforcement
# (DNS sinkhole, network isolation, USB blocking) works automatically — no
# manual "run as sudo" or dry-run juggling. The service auto-starts on boot and
# restarts on failure.
#
# Usage (as root):
#   sudo ./install-linux.sh --server https://xdr.example:8000 --token <ENROLL_TOKEN>
#
set -euo pipefail

PREFIX=/opt/silentguard
CONF_DIR=/etc/silentguard
UNIT=/etc/systemd/system/silentguard-agent.service

SERVER_URL="${SG_SERVER_URL:-}"
ENROLL_TOKEN="${SG_ENROLL_TOKEN:-}"

while [ $# -gt 0 ]; do
  case "$1" in
    --server) SERVER_URL="$2"; shift 2 ;;
    --token)  ENROLL_TOKEN="$2"; shift 2 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "ERROR: run as root (sudo)." >&2; exit 1; }
[ -n "$SERVER_URL" ] && [ -n "$ENROLL_TOKEN" ] || {
  echo "ERROR: --server <url> and --token <enroll-token> are required." >&2; exit 1; }
command -v systemctl >/dev/null || { echo "ERROR: systemd (systemctl) not found." >&2; exit 1; }

SRC="$(cd "$(dirname "$0")/.." && pwd)"   # the agent/ directory

echo "==> Installing SilentGuard agent to ${PREFIX}"
install -d "$PREFIX" "$CONF_DIR"
python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install -q --upgrade pip
"$PREFIX/venv/bin/pip" install -q -r "$SRC/requirements.txt"
rm -rf "$PREFIX/silentguard_agent"
cp -r "$SRC/silentguard_agent" "$PREFIX/"

echo "==> Writing config to ${CONF_DIR}/agent.env (0600)"
umask 077
cat > "$CONF_DIR/agent.env" <<EOF
SG_SERVER_URL=$SERVER_URL
SG_ENROLL_TOKEN=$ENROLL_TOKEN
# Enforcement is live (no SG_DRY_RUN). Add other SG_* options here if needed,
# e.g. SG_PIN_SHA256, SG_TAMPER_KEY, SG_UPDATE_PUBLIC_KEY, SG_YARA_*.
EOF
chmod 600 "$CONF_DIR/agent.env"

echo "==> Installing systemd unit"
cp "$SRC/install/silentguard-agent.service" "$UNIT"
systemctl daemon-reload
systemctl enable --now silentguard-agent

echo
echo "Done. The agent runs as root -> blocklist, isolation and USB blocking are ACTIVE."
echo "  status:  systemctl status silentguard-agent"
echo "  logs:    journalctl -u silentguard-agent -f"
