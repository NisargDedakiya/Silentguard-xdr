#!/usr/bin/env bash
# SilentGuard XDR — Linux agent uninstaller.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "ERROR: run as root (sudo)." >&2; exit 1; }

systemctl disable --now silentguard-agent 2>/dev/null || true
rm -f /etc/systemd/system/silentguard-agent.service
systemctl daemon-reload 2>/dev/null || true
rm -rf /opt/silentguard
# Keep /etc/silentguard/agent.env by default; pass --purge to remove it too.
if [ "${1:-}" = "--purge" ]; then rm -rf /etc/silentguard; fi
echo "SilentGuard agent removed. (Blocked domains in /etc/hosts are cleared on the"
echo "agent's next stop; if any remain, delete the SilentGuard block manually.)"
