# Agent Tamper Protection (v1.4)

The agent's state file (`~/.silentguard/agent_state.json`) holds its device
identity and API key. If an attacker can edit that file — to hijack the enrolled
identity, redirect the agent, or swap in a stolen key — the endpoint's trust is
compromised. The state file is now **HMAC-integrity protected** so an offline
edit is detected on the next load.

## How it works

- **Signing:** `save_state()` attaches an `_integrity` HMAC-SHA256 over the state
  (via `tamper.sign`). The file stays `0600`.
- **Verification:** on startup `TelemetryClient.ensure_enrolled()` checks the MAC
  before trusting stored credentials:
  - Valid → use the credentials as normal.
  - **Present credentials but missing/invalid MAC** → the file was tampered with:
    the stored credentials are **discarded** (the agent safely re-enrols), and a
    `tamper` event is reported.

The tamper event becomes a **critical** detection server-side via the
`tamper_detected` rule (MITRE **T1562.001**, Impair Defenses), so the SOC sees
the defense-evasion attempt.

## Integrity key

`SG_TAMPER_KEY` (recommended) provides the HMAC key from an out-of-band secret.
With no key set, the key is derived from stable machine attributes — this still
catches casual field edits, but a determined local attacker who can reproduce the
derivation is not stopped. **Set `SG_TAMPER_KEY` in production.**

## Scope

This protects the *state/credential* file, the highest-value tamper target. It
detects edits to a signed file; a real deployment should combine it with OS-level
protections (a watched service, restricted file ACLs, EDR self-protection) for
process-kill resistance. Agent-stop is already surfaced separately: the server
raises `device_unresponsive` (T1562.001) when an agent goes silent.

## Testing

`agent/tests/test_tamper.py` covers the sign/verify round-trip, field-edit
detection, missing-MAC and wrong-key rejection, that `save_state` writes a signed
file, that an authentic state enrolls cleanly, and that a tampered `api_key` is
rejected and reported. `test_detection.py::test_agent_tamper_creates_detection`
covers the server `tamper_detected` detection.
