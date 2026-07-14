# TLS Certificate Pinning (v1.4)

The agent can pin the management server's TLS certificate by its SHA-256
fingerprint. A man-in-the-middle holding a valid-but-rogue CA-issued certificate
(a corporate TLS-inspection proxy, a mis-issued or compromised CA) would pass
normal CA validation — pinning rejects it because the fingerprint won't match.

## Enabling it

Set `SG_PIN_SHA256` to the server leaf certificate's SHA-256 fingerprint (hex,
colons optional, case-insensitive):

```
SG_PIN_SHA256=AB:CD:EF:...:99
```

Compute it from the running server:

```sh
openssl s_client -connect host:443 </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256
```

Leave it unset to keep default CA-based verification only (unchanged behavior).

## How it works

`cert_pinning.build_session(config)` returns the `requests.Session` the
`TelemetryClient` uses for **every** server call (enroll, telemetry flush,
inventory, check-in). When a pin is configured, a `FingerprintAdapter` is mounted
on `https://` that passes urllib3's `assert_fingerprint` down to the connection
pool. urllib3 verifies the peer certificate's fingerprint on every connection and
raises an SSL error on mismatch — the request **fails closed**, so a MITM cannot
receive telemetry or push commands.

- Enforcement is delegated to urllib3's well-tested `assert_fingerprint`, not a
  hand-rolled check.
- Pinning composes with the existing `SG_VERIFY_TLS` CA verification.
- **Rotation:** urllib3 asserts a single fingerprint per pool. Configure one
  active pin at a time; during a cert rotation, cut over `SG_PIN_SHA256` to the
  new fingerprint as the new cert goes live (a brief maintenance step). Multiple
  comma-separated pins are accepted but only the first is enforced (with a
  warning).

## Testing

`agent/tests/test_cert_pinning.py` covers pin normalization/parsing, that a
session gets a `FingerprintAdapter` only when a pin is set, that the adapter
forwards `assert_fingerprint` into the pool manager, first-pin selection for a
multi-pin config, and that the `TelemetryClient` wires up the pinned session.
