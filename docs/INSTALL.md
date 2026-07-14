# Installing the SilentGuard Agent (enforcement enabled automatically)

The installers set the agent up as a **service that runs elevated** (root on
Linux, SYSTEM on Windows). That's what makes the *enforcement* features —
domain/URL blocklist (DNS sinkhole), device isolation, USB blocking — actually
take effect. Run manually as a normal user and those actions silently no-op; the
service model removes that failure mode entirely, auto-starts on boot, and
restarts on failure.

You need two things from the server admin: the **server URL** and the
**enrollment token** (`SG_ENROLL_TOKEN`).

## Windows

From an **Administrator** PowerShell, in the `agent\install` folder:

```powershell
.\install-windows.ps1 -ServerUrl "https://xdr.example:8000" -EnrollToken "<ENROLL_TOKEN>"
```

This will:
1. Install the agent under `C:\Program Files\SilentGuard` (its own venv).
2. Register a Scheduled Task **`SilentGuardAgent`** running as **SYSTEM** at
   startup, highest privileges, restart-on-failure — so it's always elevated.
3. **Disable browser DNS-over-HTTPS** (Chrome/Edge) via enterprise policy, so
   hosts-file domain blocking is not bypassed. (Skip with `-KeepBrowserDoH`.)
4. Flush the DNS cache.

Verify: open the dashboard timeline — you should see an **"Enforcement enabled"**
event from the device. Manage the task with `schtasks /query /tn SilentGuardAgent`.

Uninstall: `.\uninstall-windows.ps1` (add `-RestoreBrowserDoH` to re-enable DoH).

## Linux

As root, in the `agent/install` folder:

```bash
sudo ./install-linux.sh --server https://xdr.example:8000 --token <ENROLL_TOKEN>
```

This installs the agent under `/opt/silentguard`, writes config to
`/etc/silentguard/agent.env` (0600), and enables a **systemd service running as
root** that starts now and on boot.

Verify: `systemctl status silentguard-agent` and `journalctl -u silentguard-agent -f`
(look for `Enforcement enabled`).

Uninstall: `sudo ./uninstall-linux.sh` (add `--purge` to also remove the config).

## What "Enforcement enabled" means

At startup the agent reports its capability:

- **Enforcement enabled** (elevated, live): blocklist, isolation and USB control
  are active.
- **Enforcement disabled** (not elevated, or `SG_DRY_RUN=1`): telemetry and
  detection still work, but blocking/isolation will not take effect. The reason
  is shown in the log and as a dashboard event — use the installer above to fix
  it rather than running the agent by hand.

## Optional hardening (add to the config before/after install)

Add any of these to `/etc/silentguard/agent.env` (Linux) or the wrapper env
(Windows), then restart the service:

| Variable | Purpose |
|---|---|
| `SG_UPDATE_PUBLIC_KEY` | Ed25519 public key for signed agent updates |
| `SG_TAMPER_KEY` | Secret for state-file tamper protection |
| `SG_PIN_SHA256` | Pin the server's TLS certificate |
| `SG_YARA_ENABLED` / `SG_YARA_RULES` | Enable YARA file scanning |
| `SG_SURICATA_ENABLED` / `SG_SURICATA_EVE` | Ingest Suricata IDS alerts |

> The installers never set `SG_DRY_RUN`, so enforcement is live by default.
