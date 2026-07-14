# Multi-Factor Authentication (TOTP, v1.4)

Dashboard/admin accounts can protect login with a second factor — a time-based
one-time password (TOTP) from any authenticator app (Google Authenticator,
Authy, 1Password, …). The implementation is **dependency-free** (RFC 6238 over
stdlib `hmac`/`hashlib`), so no third-party library is required.

## Enrolment flow

All MFA endpoints require an authenticated session (bearer token).

1. **`POST /api/auth/mfa/setup`** → `{ "secret": "...", "otpauth_uri": "otpauth://totp/..." }`
   Generates a TOTP secret (stored but not yet enforced). Render the
   `otpauth_uri` as a QR code, or enter the `secret` manually in the app.
2. **`POST /api/auth/mfa/activate`** `{ "code": "123456" }` → `{ "enabled": true }`
   Confirms the secret with a live code and turns enforcement on. A wrong code
   returns `401`.
3. **`GET /api/auth/mfa/status`** → `{ "enabled": bool }`.
4. **`POST /api/auth/mfa/disable`** `{ "code": "123456" }` → `{ "enabled": false }`
   Requires a valid current code, so a stolen session alone cannot turn MFA off.

Both `mfa_enable` and `mfa_disable` are written to the audit log.

## Login enforcement

`POST /api/auth/login` accepts an optional `mfa_code`:

```json
{ "email": "...", "password": "...", "mfa_code": "123456" }
```

- Accounts **without** MFA are unaffected — `mfa_code` is ignored.
- Accounts **with** MFA enabled: a missing code returns `401 "MFA code required"`
  (a distinct message so the client knows to prompt), and a wrong code returns
  `401 "Invalid MFA code"`. The code check happens **after** the password is
  verified, so it never reveals whether an account exists.

Verification tolerates ±1 time step (30s) of clock skew.

## Data model

Two columns on `users` (migration `a1b2c3d4e5f6`): `mfa_enabled` (bool, default
false) and `mfa_secret` (nullable). The secret is cleared on disable.

## Testing

`server/tests/test_mfa.py` covers the TOTP core (round-trip, skew window,
bad-input rejection, epoch edge case, provisioning URI) and the full endpoint
flow: enrol → activate → login requires code → wrong code fails → correct code
succeeds → disable restores plain login, plus that non-MFA logins are unaffected.
