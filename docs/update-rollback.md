# Secure Update Rollback Protection (v1.4)

Signed updates (M15a) stop an attacker pushing *arbitrary* code. Anti-rollback
closes the remaining gap: an attacker who captured a **genuinely-signed but old**
update manifest could otherwise replay it to *downgrade* the agent to a version
with known vulnerabilities. The agent now refuses signed downgrades below the
highest version it has already accepted.

## How it works

The agent keeps a monotonic **version floor** — the highest update version it has
accepted — persisted in its tamper-protected state file (so the floor itself has
HMAC integrity). On a verified update manifest:

1. Signature is verified as before (`verify_update`). Invalid → rejected.
2. If the target version is **older than the floor** and the manifest does not
   explicitly allow rollback → rejected with `rollback_blocked`
   (`update_rejected` telemetry); the floor is left unchanged.
3. Otherwise the update is accepted, and if it is **newer** than the floor, the
   floor advances to it.

Versions are compared numerically (`1.2.0` > `1.1.9`); non-numeric targets
(e.g. `latest`) skip the rollback check.

## The rollback override is signed

A legitimate downgrade (emergency roll-back of a bad release) is expressed with
`allow_rollback: true` in the manifest. Crucially, **`allow_rollback` is part of
the signed field set**, so an attacker cannot take an old manifest that was
signed *without* the override, append `allow_rollback: true`, and force a
downgrade — doing so invalidates the signature. Only the update signer can
authorize a rollback.

## Testing

`agent/tests/test_update_rollback.py` covers version parsing/comparison,
floor-setting on accept, blocking a signed downgrade, permitting a signed
rollback when flagged, rejecting a **forged** rollback flag (signature broken),
and floor advancement on a newer version.
