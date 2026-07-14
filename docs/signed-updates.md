# Signed Agent Updates (M15a)

The management server can send a `remote_update` command to an endpoint. To stop
a compromised or spoofed management channel from pushing arbitrary code to the
fleet, an update that carries a **manifest** (a `url` and/or `sha256`) is honored
only when it is accompanied by a valid **signature** over that manifest.

Real package download/apply is still deferred; M15a delivers the trust boundary —
verification fails closed before any future delivery step can run.

## Command shapes

| Command | Fields | Behavior |
|---|---|---|
| Version-only intent | `version` | Acknowledged best-effort, flagged `verified: false`. Nothing is downloaded or executed. |
| Signed manifest | `version`, `url`, `sha256`, `signature` | Verified against the trust key. Accepted → `update_verified`; invalid/unsigned → `update_rejected` (no action). |

The signature covers a canonical, key-sorted JSON of exactly the manifest fields
(`version`, `url`, `sha256`), so server and agent agree byte-for-byte regardless
of field ordering. Transport metadata (`action_id`, …) is excluded.

## Trust keys

Provision one of the following on the endpoint (environment variables):

| Variable | Scheme | Notes |
|---|---|---|
| `SG_UPDATE_PUBLIC_KEY` | **Ed25519** (preferred) | Raw 32-byte public key as hex or base64. The private signing key stays on the server and never touches the endpoint. Requires the `cryptography` package (a declared agent dependency). |
| `SG_UPDATE_HMAC_KEY` | HMAC-SHA256 (fallback) | Shared secret, dependency-free. Signature is the hex digest, optionally prefixed `sha256=`. |
| `SG_REQUIRE_SIGNED_UPDATES` | policy | `1` (default) enforces verification on manifests; a version-only ack is always allowed. |

If both keys are set, Ed25519 takes precedence. If a manifest arrives with **no**
trust key configured, it is rejected (`no update trust key configured`) — the
verifier fails closed.

## Signing on the server side

Ed25519 (Python, using `cryptography`):

```python
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

manifest = {"version": "1.2.0", "url": "https://updates/pkg.tar", "sha256": "abc123"}
message = json.dumps({k: str(manifest[k]) for k in ("version", "url", "sha256")},
                     sort_keys=True, separators=(",", ":")).encode()
signature = private_key.sign(message).hex()
command = {"command": "remote_update", **manifest, "signature": signature}
```

HMAC-SHA256:

```python
import hashlib, hmac, json
message = json.dumps({k: str(manifest[k]) for k in ("version", "url", "sha256")},
                     sort_keys=True, separators=(",", ":")).encode()
signature = hmac.new(shared_secret.encode(), message, hashlib.sha256).hexdigest()
```

## Verification outcomes (telemetry)

| Event | When |
|---|---|
| `update_verified` (info) | Manifest signature valid; update acknowledged. |
| `update_rejected` (warning) | Missing/invalid signature, tampered manifest, or no trust key. |
| `update_requested` (info) | Version-only acknowledgement, `verified: false`. |

## Testing

`agent/tests/test_update_verifier.py` covers both schemes: HMAC valid/tampered/
prefixed, Ed25519 round-trip and wrong-key rejection, fail-closed with no key,
and the `remote_update` handler accepting a verified manifest while rejecting an
unsigned or badly-signed one. The Ed25519 cases run wherever `cryptography` is
installed and skip cleanly otherwise.
