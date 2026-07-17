# SilentGuard desktop apps

Two native Windows apps (no browser needed):

- **SilentGuard Console** (`silentguard_console`) — the **admin console as a
  desktop app**. Connects to your SilentGuard server and gives you Fleet,
  Threats, Blocklist, and Account/Members in a native window instead of a web
  page. Build: `build-console-windows.ps1` → `dist\SilentGuardConsole.exe`.
- **SilentGuard Home** (`silentguard_home`) — a standalone app that protects
  **one PC** with no server (below).

## SilentGuard Console (desktop admin app)

Build once on Windows (Python 3.11+):

```powershell
cd desktop
powershell -ExecutionPolicy Bypass -File .\build-console-windows.ps1
```

Launch `dist\SilentGuardConsole.exe`, enter your **Server URL** (e.g.
`http://your-server:8000`), and sign in with either an **admin token** or your
**email/password**. Tabs:

- **Fleet** — devices, status, risk, isolate/release.
- **Threats** — detections (time, severity, rule, device).
- **Blocklist** — add/remove domain/process/port blocks.
- **Account** — your plan + unlocked features, member list, and invite members.

Tested: `desktop/tests/test_console_api.py` (7 checks) exercises the API client
(auth, reads, block add/remove, isolate, error handling) with a fake HTTP
session. The Tkinter GUI and `.exe` can't be built/run in the Linux CI sandbox —
build on your PC and paste any errors.

---

# SilentGuard Home — standalone Windows PC protection app

A single desktop app that protects **this one PC** — no server, no browser, no
enrollment. You get a window where you add things to block (websites, programs,
ports) and it enforces them at the OS level.

This is separate from the enterprise server/agent/dashboard in the rest of the
repo; it's the "Individual" experience as a native app.

## Why this actually blocks (unlike the hosts-file-only approach)

Blocking a website with just the hosts file fails when the browser uses **Secure
DNS (DNS-over-HTTPS)**, because the browser bypasses the OS resolver. SilentGuard
Home blocks in **two layers**:

1. **Firewall (primary):** it resolves the domain to its IP addresses and adds
   **Windows Firewall** rules that drop connections to those IPs — this works
   regardless of Secure DNS, because it blocks at the network layer. IPs are
   re-checked every 30s to follow changes.
2. **Hosts file (secondary):** it also pins the domain (and `www`/`m`) to
   `0.0.0.0` as a fast local block.

Plus a **process guard** that terminates any running program on your block list.

> Honest limitation: very large CDN sites (e.g. YouTube) sit behind huge,
> constantly-changing IP pools, so firewall IP blocking is best-effort for those
> — it will block many, but a determined rotation can slip through. Smaller
> sites and specific hosts are blocked reliably.

## Build it (do this once on Windows)

You need **Python 3.11+** installed (tick "Add to PATH" in the installer).

```powershell
cd desktop
powershell -ExecutionPolicy Bypass -File .\build-windows.ps1
```

This produces **`dist\SilentGuardHome.exe`**. The `.exe` embeds an administrator
manifest, so double-clicking it raises the Windows UAC prompt automatically — no
right-click needed. Blocking requires those admin rights.

## Run it

Double-click `SilentGuardHome.exe`, accept the UAC prompt, then:

- Click **Turn on protection**.
- Pick a kind (**domain / process / port**), type a value (e.g. `youtube.com`,
  `mimikatz.exe`, `4444`), and click **Block**.
- Remove entries any time. The block list is saved in `%APPDATA%\SilentGuard`.

If the window says **"needs Administrator!"**, you launched it without elevation
— close it and re-open (accept the UAC prompt).

## What's tested vs. not (important)

This app was written in a Linux CI sandbox that has **no Windows and no display**,
so:

- ✅ **Tested** (`desktop/tests/test_home.py`, 10 checks): the block-list store,
  domain normalization, firewall command construction (Windows + Linux),
  IP resolution with subdomain expansion, the process guard, hosts-file writing,
  and the full engine sync — all with the OS calls mocked.
- ⛔ **Not runnable here:** the Tkinter GUI and the packaged `.exe` (they need
  Windows). If the build or app errors on your PC, paste the message and it can
  be fixed quickly.

## Uninstall / cleanup

Delete `SilentGuardHome.exe` and the `%APPDATA%\SilentGuard` folder. To clear any
leftover rules: remove firewall rules named `SilentGuard-Block-*` (Windows
Defender Firewall → Advanced → Outbound Rules) and delete the
`# >>> SilentGuard Home >>>` block in `C:\Windows\System32\drivers\etc\hosts`.
